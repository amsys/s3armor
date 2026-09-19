//! Multipart integration tests against a real MinIO container, driven by
//! `aws-sdk-rust` — `docs/ARCHITECTURE.md` "Integration tests" and
//! "Multipart v1". The four tests marked MANDATORY guard against a bug
//! family a shared-sequential-keystream design would produce: every part
//! here is an independent stream with its own random nonces, so retried,
//! duplicate, and out-of-order parts, and a retried Complete, are all safe
//! by construction rather than by luck.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "test code: a failed assumption should abort the test"
)]

use std::sync::Arc;
use std::time::Duration;

use aws_credential_types::Credentials;
use aws_sdk_s3::config::{BehaviorVersion, Builder, Region};
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use aws_sdk_s3::Client;
use bytes::Bytes;
use http::StatusCode;
use hyper_util::rt::TokioIo;
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};
use tokio::net::TcpListener;

use s3armor::config::{
    Backend, BindMode, ClientCredentials, Config, LogFormat, DEFAULT_BACKEND_NAME,
};
use s3armor::keys::Keyring;
use s3armor::mpu::{CachedComplete, MAX_SESSIONS};
use s3armor::proxy::{self, ProxyState};
use s3armor_format::v1::{ciphertext_len, Alg, MasterKey};

const TEST_ACCESS_KEY: &str = "testkey";
const TEST_SECRET_KEY: &str = "testsecret1234567890";
/// 64 KiB — the format's minimum — so multi-chunk parts stay cheap.
const TEST_CHUNK_SIZE: u32 = 65_536;
const TEST_MASTER_KEY: [u8; 32] = [0x77; 32];
/// Above S3's 5 MiB non-final-part minimum, so it always uploads as its own
/// part (never merged with the buffered tail) — see `small_final_part`
/// below for the other branch.
const BIG_PART: usize = 5 * 1024 * 1024 + 17;

async fn setup() -> (
    Client,
    Client,
    String,
    testcontainers::ContainerAsync<GenericImage>,
    Arc<ProxyState>,
) {
    setup_with(|_| {}).await
}

#[expect(
    clippy::too_many_lines,
    reason = "one flat sequence: start MinIO, build config, spawn the proxy, build both clients; splitting would fragment a single auditable test-setup path"
)]
async fn setup_with(
    mutate: impl FnOnce(&mut Config),
) -> (
    Client,
    Client,
    String,
    testcontainers::ContainerAsync<GenericImage>,
    Arc<ProxyState>,
) {
    let minio = GenericImage::new("quay.io/minio/minio", "RELEASE.2025-09-07T16-13-09Z")
        .with_exposed_port(9000.tcp())
        .with_wait_for(WaitFor::message_on_stderr("API:"))
        .with_env_var("MINIO_ROOT_USER", "minioadmin")
        .with_env_var("MINIO_ROOT_PASSWORD", "minioadmin")
        .with_cmd(["server", "/data"])
        .start()
        .await
        .expect("MinIO container must start — Docker must be available for this test");
    let minio_port = minio
        .get_host_port_ipv4(9000)
        .await
        .expect("MinIO exposes 9000");
    let minio_endpoint = format!("http://127.0.0.1:{minio_port}");

    let mut clients = std::collections::BTreeMap::new();
    clients.insert(
        "TEST".to_string(),
        ClientCredentials {
            access_key: TEST_ACCESS_KEY.to_string(),
            secret_key: TEST_SECRET_KEY.to_string(),
            backend: DEFAULT_BACKEND_NAME.to_string(),
        },
    );
    let mut keys = std::collections::BTreeMap::new();
    keys.insert("TEST".to_string(), MasterKey::new(TEST_MASTER_KEY));
    let keyring = Keyring::new("TEST", keys, None).expect("test keyring's active name resolves");

    let mut config = Config {
        listen: "127.0.0.1:0".to_string(),
        log_level: "error".to_string(),
        log_format: LogFormat::Text,
        backends: std::collections::BTreeMap::from([(
            DEFAULT_BACKEND_NAME.to_string(),
            Backend {
                name: DEFAULT_BACKEND_NAME.to_string(),
                endpoint: minio_endpoint.clone(),
                region: "us-east-1".to_string(),
                access_key: "minioadmin".to_string(),
                secret_key: "minioadmin".to_string(),
            },
        )]),
        clients,
        timeout_connect: Duration::from_secs(10),
        timeout_request: Duration::from_mins(5),
        keyring,
        key_active_name: "TEST".to_string(),
        chunk_size: TEST_CHUNK_SIZE,
        alg: Alg::Aes256Gcm,
        sources: std::collections::BTreeMap::default(),
        mp_ttl: Duration::from_hours(1),
        footer_cache: 1024,
        rsa_public_pem: None,
        metrics_listen: None,
        tls: None,
        auth_fail_limit: 60,
        bind_mode: BindMode::Off,
    };
    mutate(&mut config);

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind an ephemeral port");
    let proxy_addr = listener.local_addr().unwrap();
    let state = Arc::new(ProxyState::new(config));
    state.spawn_mpu_sweeper();
    let state_for_server = state.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                return;
            };
            let io = TokioIo::new(stream);
            let state = state_for_server.clone();
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |req| {
                    let state = state.clone();
                    async move { proxy::handle(state, req, peer.ip()).await }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await;
            });
        }
    });

    let endpoint = format!("http://{proxy_addr}");
    let creds = Credentials::new(TEST_ACCESS_KEY, TEST_SECRET_KEY, None, None, "static");
    let sdk_config = Builder::new()
        .region(Region::new("us-east-1"))
        .endpoint_url(&endpoint)
        .credentials_provider(creds)
        .force_path_style(true)
        .behavior_version(BehaviorVersion::latest())
        .build();
    let proxy_client = Client::from_conf(sdk_config);

    let minio_creds = Credentials::new("minioadmin", "minioadmin", None, None, "static");
    let minio_sdk_config = Builder::new()
        .region(Region::new("us-east-1"))
        .endpoint_url(&minio_endpoint)
        .credentials_provider(minio_creds)
        .force_path_style(true)
        .behavior_version(BehaviorVersion::latest())
        .build();
    let minio_client = Client::from_conf(minio_sdk_config);

    minio_client
        .create_bucket()
        .bucket("mpu-test")
        .send()
        .await
        .expect("create test bucket directly against MinIO");

    (proxy_client, minio_client, minio_endpoint, minio, state)
}

/// Deterministic pseudo-random-looking payload of `len` bytes — not random
/// (no seed plumbing needed), but not compressible or all-zero either, so a
/// bug that drops or reorders bytes shows up in a comparison.
fn payload(len: usize, tag: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(tag))
        .collect()
}

async fn create_upload(client: &Client, key: &str) -> String {
    client
        .create_multipart_upload()
        .bucket("mpu-test")
        .key(key)
        .send()
        .await
        .expect("CreateMultipartUpload")
        .upload_id()
        .expect("upload id")
        .to_string()
}

async fn upload_one(
    client: &Client,
    key: &str,
    upload_id: &str,
    number: i32,
    data: Vec<u8>,
) -> String {
    client
        .upload_part()
        .bucket("mpu-test")
        .key(key)
        .upload_id(upload_id)
        .part_number(number)
        .body(ByteStream::from(data))
        .send()
        .await
        .unwrap_or_else(|e| panic!("UploadPart {number}: {e:?}"))
        .e_tag()
        .expect("part ETag")
        .to_string()
}

async fn complete(client: &Client, key: &str, upload_id: &str, parts: Vec<(i32, String)>) {
    let completed = CompletedMultipartUpload::builder()
        .set_parts(Some(
            parts
                .into_iter()
                .map(|(n, etag)| CompletedPart::builder().part_number(n).e_tag(etag).build())
                .collect(),
        ))
        .build();
    client
        .complete_multipart_upload()
        .bucket("mpu-test")
        .key(key)
        .upload_id(upload_id)
        .multipart_upload(completed)
        .send()
        .await
        .unwrap_or_else(|e| panic!("CompleteMultipartUpload: {e:?}"));
}

async fn get_bytes(client: &Client, key: &str) -> Vec<u8> {
    client
        .get_object()
        .bucket("mpu-test")
        .key(key)
        .send()
        .await
        .unwrap_or_else(|e| panic!("GetObject {key}: {e:?}"))
        .body
        .collect()
        .await
        .expect("collect body")
        .into_bytes()
        .to_vec()
}

/// MANDATORY: a retried part (same bytes, uploaded twice) must not corrupt
/// the object. A shared sequential keystream would advance twice on a
/// retry, garbling every later byte — each part here seals independently
/// instead.
#[tokio::test]
async fn retried_part_is_safe() {
    let (client, _minio, _ep, _c, _state) = setup().await;
    let key = "retried-part.bin";
    let upload_id = create_upload(&client, key).await;
    let part1 = payload(BIG_PART, 1);
    let part2 = payload(200, 2);

    let etag1_first = upload_one(&client, key, &upload_id, 1, part1.clone()).await;
    let etag1_retry = upload_one(&client, key, &upload_id, 1, part1.clone()).await;
    let etag2 = upload_one(&client, key, &upload_id, 2, part2.clone()).await;

    // Use the retry's ETag — the last write for part 1 is what the backend
    // actually stores, real S3 semantics.
    assert_ne!(etag1_first, etag1_retry, "each seal uses a fresh nonce");
    complete(&client, key, &upload_id, vec![(1, etag1_retry), (2, etag2)]).await;

    let got = get_bytes(&client, key).await;
    let mut want = part1;
    want.extend(part2);
    assert_eq!(got, want);
}

/// MANDATORY: duplicate and out-of-order part uploads must still produce
/// the correct object. A shared-channel design would either deadlock
/// (part < expected) or corrupt every later byte (a race on a shared
/// keystream) — independent per-part streams avoid both.
#[tokio::test]
async fn duplicate_and_out_of_order_parts_are_safe() {
    let (client, _minio, _ep, _c, _state) = setup().await;
    let key = "out-of-order.bin";
    let upload_id = create_upload(&client, key).await;

    let parts: Vec<(i32, Vec<u8>)> = (1..=5).map(|n| (n, payload(BIG_PART, n as u8))).collect();
    let mut etags = std::collections::HashMap::new();
    // Upload order: 5, 1, 4, 2, 3 — deliberately not ascending, plus a
    // duplicate of part 2.
    for &n in &[5, 1, 4, 2, 2, 3] {
        let data = parts.iter().find(|(pn, _)| *pn == n).unwrap().1.clone();
        let etag = upload_one(&client, key, &upload_id, n, data).await;
        etags.insert(n, etag);
    }

    let complete_list: Vec<(i32, String)> = (1..=5).map(|n| (n, etags[&n].clone())).collect();
    complete(&client, key, &upload_id, complete_list).await;

    let got = get_bytes(&client, key).await;
    let want: Vec<u8> = parts.into_iter().flat_map(|(_, d)| d).collect();
    assert_eq!(got, want);
}

/// MANDATORY: a retried Complete (real SDKs retry it on a timeout) must
/// return the same successful response, not `NoSuchUpload`. Deleting the
/// session at Complete would break exactly this retry.
#[tokio::test]
async fn retried_complete_returns_the_cached_response() {
    let (client, _minio, _ep, _c, _state) = setup().await;
    let key = "retried-complete.bin";
    let upload_id = create_upload(&client, key).await;
    let etag = upload_one(&client, key, &upload_id, 1, payload(BIG_PART, 9)).await;

    complete(&client, key, &upload_id, vec![(1, etag.clone())]).await;
    // Second Complete with the same part list must succeed too (cached),
    // not error.
    complete(&client, key, &upload_id, vec![(1, etag)]).await;

    let got = get_bytes(&client, key).await;
    assert_eq!(got, payload(BIG_PART, 9));
}

/// MANDATORY: an upload id this node never created (simulating a restart
/// that lost the session) must fail loudly with `NoSuchUpload`, never fall
/// back to storing plaintext.
#[tokio::test]
async fn unknown_upload_id_is_rejected_not_passthrough() {
    let (client, minio, _ep, _c, _state) = setup().await;
    let key = "restart-loss.bin";

    let err = client
        .upload_part()
        .bucket("mpu-test")
        .key(key)
        .upload_id("this-upload-id-was-never-created")
        .part_number(1)
        .body(ByteStream::from(payload(1024, 1)))
        .send()
        .await
        .expect_err("UploadPart with an unknown upload id must fail");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("NoSuchUpload"),
        "expected NoSuchUpload, got: {msg}"
    );

    // And nothing was ever written to the backend under this key.
    let listing = minio
        .list_objects_v2()
        .bucket("mpu-test")
        .prefix(key)
        .send()
        .await
        .expect("ListObjectsV2 direct to MinIO");
    assert!(
        listing.contents().is_empty(),
        "no plaintext leaked to the backend"
    );
}

/// Non-contiguous client part numbers (1, 5, 9) — legal S3 — round-trip
/// correctly. Also exercises the small-final-part merge branch: the last
/// part here is small, so its ciphertext is buffered and merged with the
/// footer at Complete rather than uploaded as a doomed extra part.
#[tokio::test]
async fn noncontiguous_part_numbers_and_small_final_part_merge() {
    let (client, _minio, _ep, _c, _state) = setup().await;
    let key = "noncontiguous.bin";
    let upload_id = create_upload(&client, key).await;

    let p1 = payload(BIG_PART, 1);
    let p5 = payload(BIG_PART, 5);
    let p9 = payload(500, 9); // small final part -> merge branch

    let e1 = upload_one(&client, key, &upload_id, 1, p1.clone()).await;
    let e5 = upload_one(&client, key, &upload_id, 5, p5.clone()).await;
    let e9 = upload_one(&client, key, &upload_id, 9, p9.clone()).await;
    complete(&client, key, &upload_id, vec![(1, e1), (5, e5), (9, e9)]).await;

    let got = get_bytes(&client, key).await;
    let mut want = p1;
    want.extend(p5);
    want.extend(p9);
    assert_eq!(got, want);
}

/// The extra-part branch: every part (including the last) is above the
/// 5 MiB non-final-part minimum, so the footer uploads as its own part
/// rather than merging.
#[tokio::test]
async fn large_final_part_uses_the_extra_footer_part_branch() {
    let (client, _minio, _ep, _c, _state) = setup().await;
    let key = "large-final.bin";
    let upload_id = create_upload(&client, key).await;

    let p1 = payload(BIG_PART, 1);
    let p2 = payload(BIG_PART, 2);
    let e1 = upload_one(&client, key, &upload_id, 1, p1.clone()).await;
    let e2 = upload_one(&client, key, &upload_id, 2, p2.clone()).await;
    complete(&client, key, &upload_id, vec![(1, e1), (2, e2)]).await;

    let got = get_bytes(&client, key).await;
    let mut want = p1;
    want.extend(p2);
    assert_eq!(got, want);
}

/// HEAD reports the exact plaintext size across parts (footer-derived, not
/// a ciphertext size or a size guess).
#[tokio::test]
async fn head_reports_plaintext_size() {
    let (client, _minio, _ep, _c, _state) = setup().await;
    let key = "head-size.bin";
    let upload_id = create_upload(&client, key).await;
    let p1 = payload(BIG_PART, 1);
    let p2 = payload(300, 2);
    let e1 = upload_one(&client, key, &upload_id, 1, p1.clone()).await;
    let e2 = upload_one(&client, key, &upload_id, 2, p2.clone()).await;
    complete(&client, key, &upload_id, vec![(1, e1), (2, e2)]).await;

    let head = client
        .head_object()
        .bucket("mpu-test")
        .key(key)
        .send()
        .await
        .expect("HeadObject");
    assert_eq!(head.content_length(), Some((p1.len() + p2.len()) as i64));
}

/// A ranged GET spanning a part boundary decrypts to the exact plaintext
/// slice — proof `decrypting_multipart_range` correctly stitches parts.
#[tokio::test]
async fn ranged_get_spans_a_part_boundary() {
    let (client, _minio, _ep, _c, _state) = setup().await;
    let key = "ranged.bin";
    let upload_id = create_upload(&client, key).await;
    let p1 = payload(BIG_PART, 1);
    let p2 = payload(BIG_PART, 2);
    let e1 = upload_one(&client, key, &upload_id, 1, p1.clone()).await;
    let e2 = upload_one(&client, key, &upload_id, 2, p2.clone()).await;
    complete(&client, key, &upload_id, vec![(1, e1), (2, e2)]).await;

    let mut whole = p1.clone();
    whole.extend(p2.clone());
    let start = p1.len() - 100;
    let end = p1.len() + 100; // inclusive-friendly window straddling the boundary

    let resp = client
        .get_object()
        .bucket("mpu-test")
        .key(key)
        .range(format!("bytes={start}-{}", end - 1))
        .send()
        .await
        .expect("ranged GetObject");
    assert_eq!(
        resp.content_range(),
        Some(format!("bytes {start}-{}/{}", end - 1, whole.len()).as_str())
    );
    let got = resp.body.collect().await.expect("collect").into_bytes();
    assert_eq!(got.as_ref(), &whole[start..end]);
}

/// Corrupting a stored part's ciphertext must be rejected on GET, not
/// served as if nothing were wrong.
#[tokio::test]
async fn corrupted_part_ciphertext_is_rejected_on_get() {
    let (client, minio, _ep, _c, _state) = setup().await;
    let key = "corrupt.bin";
    let upload_id = create_upload(&client, key).await;
    let p1 = payload(BIG_PART, 1);
    let e1 = upload_one(&client, key, &upload_id, 1, p1).await;
    complete(&client, key, &upload_id, vec![(1, e1)]).await;

    // Flip one byte of the stored (ciphertext) object, direct to MinIO —
    // re-supplying the object's own `x-amz-meta-*` (a plain PutObject
    // otherwise wipes it, which would silently reroute the corrupted
    // object to passthrough instead of exercising the decrypt path at all).
    let direct = minio
        .get_object()
        .bucket("mpu-test")
        .key(key)
        .send()
        .await
        .expect("direct GetObject");
    let metadata = direct.metadata().cloned().unwrap_or_default();
    let mut obj = direct
        .body
        .collect()
        .await
        .expect("collect")
        .into_bytes()
        .to_vec();
    obj[0] ^= 0x01;
    let mut put = minio
        .put_object()
        .bucket("mpu-test")
        .key(key)
        .body(ByteStream::from(obj));
    for (k, v) in &metadata {
        put = put.metadata(k, v);
    }
    put.send()
        .await
        .expect("direct PutObject of the corrupted bytes");

    let err = client
        .get_object()
        .bucket("mpu-test")
        .key(key)
        .send()
        .await
        .expect("GetObject starts successfully (streaming failure comes later)");
    let result = err.body.collect().await;
    assert!(
        result.is_err(),
        "a corrupted multipart object must not stream out as if it were valid plaintext"
    );
}

/// Abort frees the session: a subsequent UploadPart on the same upload id
/// fails with `NoSuchUpload`.
#[tokio::test]
async fn abort_frees_the_session() {
    let (client, _minio, _ep, _c, state) = setup().await;
    let key = "abort.bin";
    let upload_id = create_upload(&client, key).await;
    assert_eq!(state.mpu_sessions_active(), 1);

    client
        .abort_multipart_upload()
        .bucket("mpu-test")
        .key(key)
        .upload_id(&upload_id)
        .send()
        .await
        .expect("AbortMultipartUpload");
    assert_eq!(state.mpu_sessions_active(), 0);

    let err = client
        .upload_part()
        .bucket("mpu-test")
        .key(key)
        .upload_id(&upload_id)
        .part_number(1)
        .body(ByteStream::from(payload(10, 1)))
        .send()
        .await
        .expect_err("UploadPart after Abort must fail");
    assert!(format!("{err:?}").contains("NoSuchUpload"));
}

/// Contract pin: an UploadPart after a successful Complete fails with
/// `NoSuchUpload`, both before and after `Session::finish` releases the
/// session's DEK — the backend already answers this way today, since a
/// completed upload id is no longer open on the backend either.
#[tokio::test]
async fn upload_part_after_complete_is_no_such_upload() {
    let (client, _minio, _ep, _c, _state) = setup().await;
    let key = "after-complete.bin";
    let upload_id = create_upload(&client, key).await;
    let e1 = upload_one(&client, key, &upload_id, 1, payload(BIG_PART, 1)).await;
    complete(&client, key, &upload_id, vec![(1, e1)]).await;

    let err = client
        .upload_part()
        .bucket("mpu-test")
        .key(key)
        .upload_id(&upload_id)
        .part_number(2)
        .body(ByteStream::from(payload(10, 2)))
        .send()
        .await
        .expect_err("UploadPart after Complete must fail");
    assert!(format!("{err:?}").contains("NoSuchUpload"));
}

/// `UploadPartCopy` is explicitly unsupported in v1 (ciphertext cannot be
/// re-chunked server-side) — must fail loudly, never silently corrupt.
#[tokio::test]
async fn upload_part_copy_is_not_implemented() {
    let (client, _minio, _ep, _c, _state) = setup().await;
    let src_key = "copy-source.bin";
    let upload_id_src = create_upload(&client, src_key).await;
    let e1 = upload_one(&client, src_key, &upload_id_src, 1, payload(BIG_PART, 1)).await;
    complete(&client, src_key, &upload_id_src, vec![(1, e1)]).await;

    let dst_key = "copy-dest.bin";
    let upload_id_dst = create_upload(&client, dst_key).await;
    let err = client
        .upload_part_copy()
        .bucket("mpu-test")
        .key(dst_key)
        .upload_id(&upload_id_dst)
        .part_number(1)
        .copy_source(format!("mpu-test/{src_key}"))
        .send()
        .await
        .expect_err("UploadPartCopy must be rejected");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("NotImplemented") || msg.contains("501"),
        "expected NotImplemented, got: {msg}"
    );
}

/// `GetObject` with `?partNumber` (no `uploadId`) — fetching one part of an
/// already completed object — is explicitly unsupported in v1, same
/// posture as `UploadPartCopy` above: fail loudly, never silently return
/// the wrong bytes.
#[tokio::test]
async fn get_object_with_part_number_is_not_implemented() {
    let (client, _minio, _ep, _c, _state) = setup().await;
    let key = "get-part.bin";
    let upload_id = create_upload(&client, key).await;
    let e1 = upload_one(&client, key, &upload_id, 1, payload(BIG_PART, 1)).await;
    complete(&client, key, &upload_id, vec![(1, e1)]).await;

    let err = client
        .get_object()
        .bucket("mpu-test")
        .key(key)
        .part_number(1)
        .send()
        .await
        .expect_err("GetObject with partNumber must be rejected");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("NotImplemented") || msg.contains("501"),
        "expected NotImplemented, got: {msg}"
    );
}

/// XChaCha20-Poly1305 — the algorithm the CPU-autoselect picks on hosts
/// without AES-NI (`README.md`'s "picked automatically for the CPU it runs
/// on") — round-trips multipart correctly. The footer frame carries `alg`
/// in its own record (`crates/s3armor-format/src/v1/footer.rs`), so this needs
/// its own proof beyond `xchacha20_round_trip_matches_the_aes_path` in
/// `integration_minio.rs`, which only covers single-part.
#[tokio::test]
async fn xchacha20_multipart_round_trip_matches_the_aes_path() {
    let (client, _minio, _ep, _c, _state) =
        setup_with(|cfg| cfg.alg = Alg::XChaCha20Poly1305).await;
    let key = "xchacha20-multipart.bin";
    let upload_id = create_upload(&client, key).await;
    let p1 = payload(BIG_PART, 1);
    let p2 = payload(300, 2);
    let e1 = upload_one(&client, key, &upload_id, 1, p1.clone()).await;
    let e2 = upload_one(&client, key, &upload_id, 2, p2.clone()).await;
    complete(&client, key, &upload_id, vec![(1, e1), (2, e2)]).await;

    let head = client
        .head_object()
        .bucket("mpu-test")
        .key(key)
        .send()
        .await
        .expect("HeadObject");
    assert_eq!(head.content_length(), Some((p1.len() + p2.len()) as i64));

    let got = get_bytes(&client, key).await;
    let mut want = p1;
    want.extend(p2);
    assert_eq!(got, want);
}

/// No `x-amz-meta-s3a-*` bookkeeping key ever reaches the client, on a
/// multipart object.
#[tokio::test]
async fn no_s3armor_metadata_leaks_on_multipart_objects() {
    let (client, _minio, _ep, _c, _state) = setup().await;
    let key = "no-leak.bin";
    let upload_id = create_upload(&client, key).await;
    let e1 = upload_one(&client, key, &upload_id, 1, payload(BIG_PART, 1)).await;
    complete(&client, key, &upload_id, vec![(1, e1)]).await;

    let head = client
        .head_object()
        .bucket("mpu-test")
        .key(key)
        .send()
        .await
        .expect("HeadObject");
    let metadata = head.metadata().cloned().unwrap_or_default();
    for k in metadata.keys() {
        assert!(!k.starts_with("s3a-"), "leaked s3armor metadata key: {k}");
    }
}

/// The footer cache: a second GET on the same object hits the cache
/// instead of re-fetching the trailer and frame.
#[tokio::test]
async fn footer_cache_hits_on_second_read() {
    let (client, _minio, _ep, _c, state) = setup().await;
    let key = "footer-cache.bin";
    let upload_id = create_upload(&client, key).await;
    let e1 = upload_one(&client, key, &upload_id, 1, payload(BIG_PART, 1)).await;
    complete(&client, key, &upload_id, vec![(1, e1)]).await;

    let _ = get_bytes(&client, key).await;
    let misses_after_first = state.footer_cache_misses();
    let hits_after_first = state.footer_cache_hits();
    assert!(misses_after_first >= 1);

    let _ = get_bytes(&client, key).await;
    assert!(state.footer_cache_hits() > hits_after_first);
    assert_eq!(state.footer_cache_misses(), misses_after_first);
}

/// `S3A_MP_TTL` expiry: a session older than the configured TTL is swept,
/// so a stale upload id fails with `NoSuchUpload`. `setup`'s own
/// `spawn_mpu_sweeper` ticks every 60s (the production interval), so this
/// test spawns a second, fast-ticking sweeper directly on the same
/// `ProxyState` — same predicate, observable without a minute-long sleep.
///
/// The sweep must also abort the backend's own multipart
/// upload, not just drop the in-RAM session — otherwise an abandoned
/// upload's parts stay on the backend, billed, forever. Asserted here via
/// `ListMultipartUploads` directly against MinIO.
#[tokio::test]
async fn mp_ttl_expiry_sweeps_stale_sessions() {
    let ttl = Duration::from_millis(300);
    let (client, minio, _ep, _c, state) = setup_with(|c| {
        c.mp_ttl = ttl;
    })
    .await;
    let key = "ttl.bin";
    let upload_id = create_upload(&client, key).await;
    assert_eq!(state.mpu_sessions_active(), 1);

    state.spawn_mpu_sweeper_with_tick(ttl, Duration::from_millis(100));
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(
        state.mpu_sessions_active(),
        0,
        "the fast sweeper must have reaped the expired session"
    );

    let err = client
        .upload_part()
        .bucket("mpu-test")
        .key(key)
        .upload_id(&upload_id)
        .part_number(1)
        .body(ByteStream::from(payload(10, 1)))
        .send()
        .await
        .expect_err("UploadPart on a swept upload id must fail");
    assert!(format!("{err:?}").contains("NoSuchUpload"));

    let uploads = minio
        .list_multipart_uploads()
        .bucket("mpu-test")
        .send()
        .await
        .expect("ListMultipartUploads");
    assert!(
        uploads.uploads().is_empty(),
        "the sweeper must have aborted the backend upload, not just dropped the session: {:?}",
        uploads.uploads()
    );
}

/// Smallest plaintext length whose ciphertext hits exactly S3's 5 MiB
/// non-final-part minimum at the test chunk size/algorithm —
/// `intercept::mpu::handle_upload_part`'s tail-buffer switch is
/// `ct_len < MIN_PART_SIZE`, so this is the exact byte where the branch
/// flips.
fn tail_buffer_boundary_pt_len() -> u64 {
    const MIN_PART_SIZE: u64 = 5 * 1024 * 1024;
    let (mut lo, mut hi) = (0u64, MIN_PART_SIZE);
    while lo < hi {
        let mid = u64::midpoint(lo, hi);
        if ciphertext_len(Alg::Aes256Gcm, mid, u64::from(TEST_CHUNK_SIZE)) >= MIN_PART_SIZE {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    lo
}

/// The 5 MiB tail-buffer switch (`intercept::mpu.rs:174`,
/// `ct_len < MIN_PART_SIZE`) selects between buffering the final part whole
/// (merged with the footer at Complete) and streaming it as its own part.
/// Getting the comparison wrong by one byte sends a sub-5-MiB part to the
/// backend as a middle part, and MinIO rejects the whole
/// `CompleteMultipartUpload` with `EntityTooSmall` — this test needs no
/// branch introspection, a wrong boundary fails it directly. Covers the
/// byte immediately below, at, and immediately above the switch.
#[tokio::test]
async fn tail_buffer_switch_at_the_exact_5mib_ciphertext_boundary() {
    let (client, _minio, _ep, _c, _state) = setup().await;
    let boundary = tail_buffer_boundary_pt_len();

    for (label, final_len) in [
        ("below", boundary - 1), // ct_len < 5 MiB: buffered, merges with footer
        ("at", boundary),        // ct_len == 5 MiB: not buffered, own part
        ("above", boundary + 1), // ct_len > 5 MiB: not buffered, own part
    ] {
        let key = format!("tail-boundary-{label}.bin");
        let upload_id = create_upload(&client, &key).await;
        let p1 = payload(BIG_PART, 1);
        let p2 = payload(final_len as usize, 2);
        let e1 = upload_one(&client, &key, &upload_id, 1, p1.clone()).await;
        let e2 = upload_one(&client, &key, &upload_id, 2, p2.clone()).await;
        complete(&client, &key, &upload_id, vec![(1, e1), (2, e2)]).await;

        let got = get_bytes(&client, &key).await;
        let mut want = p1;
        want.extend(p2);
        assert_eq!(got, want, "{label} boundary (final_len={final_len})");

        let head = client
            .head_object()
            .bucket("mpu-test")
            .key(&key)
            .send()
            .await
            .unwrap_or_else(|e| panic!("HeadObject {label}: {e:?}"));
        assert_eq!(
            head.content_length(),
            Some(want.len() as i64),
            "{label} boundary HEAD content-length"
        );

        // A ranged read crossing the boundary between the two parts.
        let split = BIG_PART as u64;
        let resp = client
            .get_object()
            .bucket("mpu-test")
            .key(&key)
            .range(format!("bytes={}-{}", split - 1, split))
            .send()
            .await
            .unwrap_or_else(|e| panic!("ranged get {label}: {e:?}"));
        let bytes = resp.body.collect().await.unwrap().into_bytes();
        assert_eq!(
            bytes.as_ref(),
            &want[(split - 1) as usize..=(split as usize)],
            "{label} boundary ranged get"
        );
    }
}

/// A legal S3 pattern: Complete lists a subset of the uploaded parts,
/// dropping an unreferenced one. Part 3 (small) displaces part 2's (small)
/// tail buffer before Complete finishes with part 2 — without buffering
/// every sub-5-MiB part, this fell back to sealing the footer as its own
/// extra part, leaving part 2 as an under-5-MiB middle part the backend
/// rejects with `EntityTooSmall`.
#[tokio::test]
async fn complete_with_a_subset_of_parts_still_merges_the_right_tail() {
    let (client, _minio, _ep, _c, _state) = setup().await;
    let key = "subset-complete.bin";
    let upload_id = create_upload(&client, key).await;

    let p1 = payload(BIG_PART, 1);
    let p2 = payload(500, 2);
    let p3 = payload(500, 3);
    let e1 = upload_one(&client, key, &upload_id, 1, p1.clone()).await;
    let e2 = upload_one(&client, key, &upload_id, 2, p2.clone()).await;
    let _e3 = upload_one(&client, key, &upload_id, 3, p3).await;
    // Complete with [1, 2] only — part 3 is uploaded but never referenced,
    // same as real S3 allows.
    complete(&client, key, &upload_id, vec![(1, e1), (2, e2)]).await;

    let got = get_bytes(&client, key).await;
    let mut want = p1;
    want.extend(p2);
    assert_eq!(got, want);
}

/// Adversarial version of the subset-complete test above: instead of one
/// displacing part, upload enough small "decoy" parts to exceed
/// `mpu::MAX_TAIL_BYTES` (three sub-5-MiB parts' worth) and evict the part
/// the client actually intends to finish with. Complete must fail loudly
/// with `InvalidPart` — the documented remaining gap — never corrupt the
/// object or panic.
#[tokio::test]
async fn complete_referencing_a_tail_evicted_by_decoy_parts_fails_cleanly() {
    // ~4 MiB plaintext -> ~4.0 MiB ciphertext at the test chunk size,
    // safely under the 5 MiB tail-buffering threshold. Five of these
    // exceed the 15 MiB tail cap, evicting the lowest part numbers first.
    const SMALL: usize = 4 * 1024 * 1024;

    let (client, minio, _ep, _c, _state) = setup().await;
    let key = "evicted-tail.bin";
    let upload_id = create_upload(&client, key).await;
    let mut etags = Vec::new();
    for n in 1..=5 {
        etags.push(upload_one(&client, key, &upload_id, n, payload(SMALL, n as u8)).await);
    }

    // A legal S3 pattern (parts 3-5 are simply discarded) — but parts 1
    // and 2 were evicted from the tail buffer by parts 3, 4, 5 landing
    // after them, so part 2 (the real last part here) is no longer
    // buffered when Complete runs.
    let completed = CompletedMultipartUpload::builder()
        .set_parts(Some(vec![
            CompletedPart::builder()
                .part_number(1)
                .e_tag(etags[0].clone())
                .build(),
            CompletedPart::builder()
                .part_number(2)
                .e_tag(etags[1].clone())
                .build(),
        ]))
        .build();
    let err = client
        .complete_multipart_upload()
        .bucket("mpu-test")
        .key(key)
        .upload_id(&upload_id)
        .multipart_upload(completed)
        .send()
        .await
        .expect_err("Complete referencing an evicted tail part must fail, not corrupt");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("InvalidPart"),
        "expected InvalidPart, got: {msg}"
    );

    // Nothing was ever sealed under this key — no half-written object.
    let listing = minio
        .list_objects_v2()
        .bucket("mpu-test")
        .prefix(key)
        .send()
        .await
        .expect("ListObjectsV2 direct to MinIO");
    assert!(
        listing.contents().iter().all(|o| o.key() != Some(key)),
        "no object should exist at {key} after a failed Complete"
    );
}

fn synthetic_key(i: usize) -> s3armor::mpu::SessionKey {
    (
        DEFAULT_BACKEND_NAME.to_string(),
        "mpu-test".to_string(),
        format!("synthetic-{i}"),
        format!("synthetic-upload-{i}"),
    )
}

/// Adds open synthetic sessions until the node is at `MAX_SESSIONS`.
fn fill_to_the_cap(state: &ProxyState) {
    let mut i = 0;
    while state.sessions.len() < MAX_SESSIONS {
        assert!(state.sessions.create(
            synthetic_key(i),
            [0u8; 32],
            Alg::Aes256Gcm,
            TEST_CHUNK_SIZE
        ));
        i += 1;
    }
}

const fn finished() -> CachedComplete {
    CachedComplete {
        status: StatusCode::OK,
        headers: Vec::new(),
        body: Bytes::new(),
    }
}

/// Abort after a successful Complete removes the finished session. The
/// completed object stays, and a retried Complete then gets `NoSuchUpload`.
#[tokio::test]
async fn abort_after_complete_keeps_the_object_and_drops_the_session() {
    let (client, _minio, _ep, _c, state) = setup().await;
    let key = "abort-after-complete.bin";
    let upload_id = create_upload(&client, key).await;
    let e1 = upload_one(&client, key, &upload_id, 1, payload(BIG_PART, 1)).await;
    complete(&client, key, &upload_id, vec![(1, e1.clone())]).await;

    // The backend answer for a finished upload id is not the same on each backend.
    let _ = client
        .abort_multipart_upload()
        .bucket("mpu-test")
        .key(key)
        .upload_id(&upload_id)
        .send()
        .await;

    // Guards: `handle_abort` removes the session after each backend response.
    assert_eq!(get_bytes(&client, key).await, payload(BIG_PART, 1));
    assert_eq!(state.mpu_sessions_active(), 0);
    let completed = CompletedMultipartUpload::builder()
        .parts(CompletedPart::builder().part_number(1).e_tag(e1).build())
        .build();
    let err = client
        .complete_multipart_upload()
        .bucket("mpu-test")
        .key(key)
        .upload_id(&upload_id)
        .multipart_upload(completed)
        .send()
        .await
        .expect_err("Complete after Abort must fail");
    assert!(format!("{err:?}").contains("NoSuchUpload"));
}

/// At the cap, a new upload evicts the one finished session.
#[tokio::test]
async fn create_at_the_cap_evicts_a_finished_session() {
    let (client, _minio, _ep, _c, state) = setup().await;
    fill_to_the_cap(&state);
    let victim = synthetic_key(0);
    state.sessions.get_mut(&victim).unwrap().finish(finished());

    let _upload_id = create_upload(&client, "cap-evict.bin").await;

    // Guards: the `make_room` call before the backend call in `handle_create`.
    let evicted = state.sessions.get(&victim).is_none();
    assert!(evicted);
    assert_eq!(state.sessions.len(), MAX_SESSIONS);
}

/// At the cap with only open sessions, Create is `SlowDown`, and the proxy
/// starts no upload on the backend.
#[tokio::test]
async fn create_at_the_cap_with_only_open_sessions_is_slow_down_and_starts_no_backend_upload() {
    let (client, minio, _ep, _c, state) = setup().await;
    fill_to_the_cap(&state);

    let err = client
        .create_multipart_upload()
        .bucket("mpu-test")
        .key("cap-full.bin")
        .send()
        .await
        .expect_err("Create at the cap with only open sessions must fail");

    // Guards: `handle_create` returns `SlowDown` before it calls the backend.
    assert!(format!("{err:?}").contains("SlowDown"));
    let uploads = minio
        .list_multipart_uploads()
        .bucket("mpu-test")
        .send()
        .await
        .expect("ListMultipartUploads");
    assert!(
        uploads.uploads().is_empty(),
        "no backend upload may start: {:?}",
        uploads.uploads()
    );
}

/// Known limit (docs/ARCHITECTURE.md "Garbage collection"): when cap
/// pressure evicts a finished session, a retried Complete for it gets
/// `NoSuchUpload`. The object itself stays.
#[tokio::test]
async fn a_retried_complete_after_eviction_at_the_cap_is_no_such_upload() {
    let (client, _minio, _ep, _c, state) = setup().await;
    let key = "first.bin";
    let upload_id = create_upload(&client, key).await;
    let e1 = upload_one(&client, key, &upload_id, 1, payload(BIG_PART, 1)).await;
    complete(&client, key, &upload_id, vec![(1, e1.clone())]).await;
    fill_to_the_cap(&state);

    let _second = create_upload(&client, "second.bin").await;

    // Guards: `make_room` evicts the finished session and its cached response.
    let completed = CompletedMultipartUpload::builder()
        .parts(CompletedPart::builder().part_number(1).e_tag(e1).build())
        .build();
    let err = client
        .complete_multipart_upload()
        .bucket("mpu-test")
        .key(key)
        .upload_id(&upload_id)
        .multipart_upload(completed)
        .send()
        .await
        .expect_err("a retried Complete after eviction must fail");
    assert!(format!("{err:?}").contains("NoSuchUpload"));
    assert_eq!(get_bytes(&client, key).await, payload(BIG_PART, 1));
}
