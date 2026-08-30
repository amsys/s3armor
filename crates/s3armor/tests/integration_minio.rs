//! Integration test against a real MinIO container, driven by
//! `aws-sdk-rust` as the client — `docs/ARCHITECTURE.md` "Integration tests". Fails, never
//! skips, when Docker is unavailable: `AsyncRunner::start()` returns an
//! `Err` in that case, which this test propagates via `.expect(...)`
//! rather than swallowing.
//!
//! Passthrough tests below prove the passthrough architecture itself —
//! SigV4 verify (header and presigned), re-signing, streaming request/response
//! bodies including `aws-chunked` with a checksum trailer, ranges, and the
//! backend's own List/Head/Delete XML coming back untouched.
//!
//! Format-v1 interception tests prove: PUT encrypts, GET/HEAD decrypt,
//! the object at rest is genuinely ciphertext, ranges decrypt to the exact
//! plaintext slice, and corruption at rest is rejected rather than served.

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
use aws_sdk_s3::types::{
    CompletedMultipartUpload, CompletedPart, CsvInput, CsvOutput, ExpressionType,
    InputSerialization, OutputSerialization,
};
use aws_sdk_s3::Client;
use hyper_util::rt::TokioIo;
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

use s3armor::config::{
    Backend, BindMode, ClientCredentials, Config, LogFormat, DEFAULT_BACKEND_NAME,
};
use s3armor::keys::Keyring;
use s3armor::proxy::{self, ProxyState};
use s3armor_format::v1::{ciphertext_len, Alg, MasterKey};

const TEST_ACCESS_KEY: &str = "testkey";
const TEST_SECRET_KEY: &str = "testsecret1234567890";
/// 64 KiB — the format's minimum — so multi-chunk tests stay cheap.
const TEST_CHUNK_SIZE: u32 = 65_536;
const TEST_MASTER_KEY: [u8; 32] = [0x42; 32];

/// Starts MinIO in a container and the s3armor proxy in-process (as a spawned
/// tokio task, not a subprocess — same binary code path, faster to start).
/// Returns an S3 SDK client pointed at the proxy, the proxy's own endpoint,
/// MinIO's own endpoint (for at-rest assertions with a second, direct SDK
/// client), and the MinIO container (kept alive by holding it).
async fn setup() -> (
    Client,
    String,
    String,
    testcontainers::ContainerAsync<GenericImage>,
) {
    setup_with(|_| {}).await
}

/// Builds a `Config` against `minio_endpoint`, `mutate`s it, and spawns a
/// proxy instance for it as an in-process tokio task. Returns an SDK client
/// pointed at the new proxy and its endpoint. Factored out of `setup_with`
/// so a test can start a *second* proxy (a different `Config`, e.g. a
/// different `bind_mode`) against the same already-running MinIO container
/// — modeling an operator restarting the proxy with a changed env var,
/// not a fresh backend.
async fn spawn_proxy(minio_endpoint: &str, mutate: impl FnOnce(&mut Config)) -> (Client, String) {
    let (client, endpoint, _state) = spawn_proxy_with_state(minio_endpoint, mutate).await;
    (client, endpoint)
}

/// Like [`spawn_proxy`], also returning the `Arc<ProxyState>` — for
/// tests that need to drive `ProxyState::set_draining` directly, since this
/// harness's accept loop is a simplified stand-in for `main::serve` (it
/// exists to exercise `proxy::handle`, not `serve`'s own shutdown
/// machinery, which is Docker-image-level and covered by
/// `scripts/lifecycle-check.sh` instead).
async fn spawn_proxy_with_state(
    minio_endpoint: &str,
    mutate: impl FnOnce(&mut Config),
) -> (Client, String, Arc<ProxyState>) {
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
                endpoint: minio_endpoint.to_string(),
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
    let returned_state = state.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                return;
            };
            let io = TokioIo::new(stream);
            let state = state.clone();
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
    (Client::from_conf(sdk_config), endpoint, returned_state)
}

/// Like [`setup`], but `mutate` runs on the `Config` before the proxy
/// starts — e.g. to point `S3A_ALG` at XChaCha20-Poly1305 for a test.
async fn setup_with(
    mutate: impl FnOnce(&mut Config),
) -> (
    Client,
    String,
    String,
    testcontainers::ContainerAsync<GenericImage>,
) {
    let minio = GenericImage::new("minio/minio", "latest")
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
    let (client, endpoint) = spawn_proxy(&minio_endpoint, mutate).await;
    (client, endpoint, minio_endpoint, minio)
}

/// An SDK client pointed straight at MinIO (bypassing the proxy entirely),
/// for asserting what actually landed at rest.
fn minio_client(minio_endpoint: &str) -> Client {
    let creds = Credentials::new("minioadmin", "minioadmin", None, None, "static");
    let sdk_config = Builder::new()
        .region(Region::new("us-east-1"))
        .endpoint_url(minio_endpoint)
        .credentials_provider(creds)
        .force_path_style(true)
        .behavior_version(BehaviorVersion::latest())
        .build();
    Client::from_conf(sdk_config)
}

#[tokio::test]
async fn passthrough_round_trip_covers_the_full_object_lifecycle() {
    let (client, _endpoint, _minio_endpoint, _minio) = setup().await;
    let bucket = "passthrough-lifecycle";
    let key = "a folder/héllo world.txt"; // space + UTF-8: a SigV4 canonicalization edge case
    let body = b"hello proxy world";

    client
        .create_bucket()
        .bucket(bucket)
        .send()
        .await
        .expect("create bucket");

    let put = client
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(ByteStream::from_static(body))
        .send()
        .await
        .expect("put object with a space+UTF-8 key");
    assert!(
        put.e_tag().is_some(),
        "PUT must return an ETag (docs/ARCHITECTURE.md \"ETag policy\")"
    );

    let got = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .expect("get object");
    let bytes = got.body.collect().await.unwrap().into_bytes();
    assert_eq!(bytes.as_ref(), body);

    let head = client
        .head_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .expect("head object");
    assert_eq!(head.content_length(), Some(body.len() as i64));

    let listed = client
        .list_objects_v2()
        .bucket(bucket)
        .send()
        .await
        .expect("list objects");
    assert_eq!(listed.contents().len(), 1);
    assert_eq!(listed.contents()[0].key(), Some(key));

    let ranged = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .range("bytes=0-4")
        .send()
        .await
        .expect("ranged get");
    let content_range = ranged.content_range().map(str::to_string);
    let range_bytes = ranged.body.collect().await.unwrap().into_bytes();
    assert_eq!(range_bytes.as_ref(), &body[..5]);
    assert!(
        content_range.is_some(),
        "a 206 range response must carry Content-Range"
    );

    client
        .delete_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .expect("delete object");
    let after_delete = client
        .list_objects_v2()
        .bucket(bucket)
        .send()
        .await
        .expect("list after delete");
    assert_eq!(after_delete.contents().len(), 0);
}

#[tokio::test]
async fn large_body_forces_aws_chunked_and_round_trips_byte_exact() {
    let (client, _endpoint, _minio_endpoint, _minio) = setup().await;
    let bucket = "passthrough-large-object";
    client
        .create_bucket()
        .bucket(bucket)
        .send()
        .await
        .expect("create bucket");

    // Large enough that the SDK switches to aws-chunked streaming with a
    // checksum trailer (`STREAMING-...-PAYLOAD-TRAILER`) instead of
    // buffering — this is the path `chunked::Dechunker` +
    // `ChunkVerifier` exist for, and (at 64 KiB chunks) a multi-frame v1
    // encrypt/decrypt too.
    let payload: Vec<u8> = (0..8_000_000u32).map(|i| (i % 251) as u8).collect();
    client
        .put_object()
        .bucket(bucket)
        .key("big.bin")
        .body(ByteStream::from(payload.clone()))
        .send()
        .await
        .expect("put large object");

    let got = client
        .get_object()
        .bucket(bucket)
        .key("big.bin")
        .send()
        .await
        .expect("get large object");
    let bytes = got.body.collect().await.unwrap().into_bytes();
    assert_eq!(bytes.len(), payload.len());
    assert_eq!(bytes.as_ref(), payload.as_slice());
}

#[tokio::test]
async fn presigned_put_and_get_are_accepted() {
    let (client, _endpoint, _minio_endpoint, _minio) = setup().await;
    let bucket = "presigned-requests";
    client
        .create_bucket()
        .bucket(bucket)
        .send()
        .await
        .expect("create bucket");

    let presign_conf =
        aws_sdk_s3::presigning::PresigningConfig::expires_in(Duration::from_mins(5)).unwrap();
    let presigned_put = client
        .put_object()
        .bucket(bucket)
        .key("presigned.txt")
        .presigned(presign_conf.clone())
        .await
        .expect("build presigned PUT");

    let http_client: hyper_util::client::legacy::Client<_, http_body_util::Full<bytes::Bytes>> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();
    let mut builder = http::Request::put(presigned_put.uri());
    for (name, value) in presigned_put.headers() {
        builder = builder.header(name, value);
    }
    let req = builder
        .body(http_body_util::Full::new(bytes::Bytes::from_static(
            b"presigned body",
        )))
        .unwrap();
    let resp = http_client
        .request(req)
        .await
        .expect("presigned PUT reaches the proxy");
    assert!(
        resp.status().is_success(),
        "presigned PUT must succeed, got {}",
        resp.status()
    );

    let presigned_get = client
        .get_object()
        .bucket(bucket)
        .key("presigned.txt")
        .presigned(presign_conf)
        .await
        .expect("build presigned GET");
    let get_req = http::Request::get(presigned_get.uri())
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .unwrap();
    let empty_client: hyper_util::client::legacy::Client<_, http_body_util::Empty<bytes::Bytes>> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();
    let get_resp = empty_client
        .request(get_req)
        .await
        .expect("presigned GET reaches the proxy");
    assert!(
        get_resp.status().is_success(),
        "presigned GET must succeed, got {}",
        get_resp.status()
    );
}

#[tokio::test]
async fn a_bucket_subresource_operation_returns_the_backends_own_xml_untouched() {
    let (client, _endpoint, _minio_endpoint, _minio) = setup().await;
    let bucket = "bucket-subresource-passthrough";
    client
        .create_bucket()
        .bucket(bucket)
        .send()
        .await
        .expect("create bucket");

    // No interceptor exists for GetBucketLocation — this only succeeds if
    // the request reached the backend and the backend's own XML came back
    // parseable by the SDK, exactly the passthrough promise of docs/ARCHITECTURE.md "Architecture: re-signing streaming reverse proxy".
    let loc = client.get_bucket_location().bucket(bucket).send().await;
    assert!(
        loc.is_ok(),
        "bucket sub-resource passthrough must return backend-parseable XML: {loc:?}"
    );
}

#[tokio::test]
async fn unauthenticated_and_tampered_requests_are_rejected_before_reaching_the_backend() {
    let (client, endpoint, _minio_endpoint, _minio) = setup().await;

    // Route straight at the proxy without going through the SDK, since the
    // SDK will not construct an invalid signature for us.
    let bucket = "rejects-bad-auth";
    client
        .create_bucket()
        .bucket(bucket)
        .send()
        .await
        .expect("create bucket");

    let http_client: hyper_util::client::legacy::Client<_, http_body_util::Empty<bytes::Bytes>> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();

    let no_auth_req = http::Request::get(format!("{endpoint}/{bucket}"))
        .body(http_body_util::Empty::new())
        .unwrap();
    let resp = http_client.request(no_auth_req).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);

    let bad_sig_req = http::Request::get(format!("{endpoint}/{bucket}"))
        .header(
            "Authorization",
            "AWS4-HMAC-SHA256 Credential=testkey/20260101/us-east-1/s3/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=0000000000000000000000000000000000000000000000000000000000000000",
        )
        .header(
            "x-amz-date",
            s3armor::sigv4::time::format_amz_date(std::time::SystemTime::now()),
        )
        .body(http_body_util::Empty::new())
        .unwrap();
    let resp = http_client.request(bad_sig_req).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
}

// --- single-part crypto -----------------------------------------------------

#[tokio::test]
async fn put_get_round_trip_is_byte_exact_and_at_rest_is_ciphertext() {
    let (client, _endpoint, minio_endpoint, _minio) = setup().await;
    let bucket = "crypto-roundtrip";
    let key = "a dir/café.txt"; // space-free but UTF-8; matches passthrough-check.sh's regression key
                                // A little over 3 chunks at the 64 KiB test chunk size, so this
                                // exercises the multi-frame encryptor/decryptor, not just one frame.
    let plaintext: Vec<u8> = (0..200_000u32).map(|i| (i % 256) as u8).collect();

    client
        .create_bucket()
        .bucket(bucket)
        .send()
        .await
        .expect("create bucket");
    client
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(ByteStream::from(plaintext.clone()))
        .send()
        .await
        .expect("put object");

    let got = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .expect("get object");
    assert_eq!(
        got.content_length(),
        Some(plaintext.len() as i64),
        "GET Content-Length must be the plaintext length, not the ciphertext length"
    );
    let bytes = got.body.collect().await.unwrap().into_bytes();
    assert_eq!(bytes.as_ref(), plaintext.as_slice());

    let head = client
        .head_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .expect("head object");
    assert_eq!(head.content_length(), Some(plaintext.len() as i64));

    // At rest, straight against MinIO: ciphertext, v1 metadata, and the
    // stored size matches the format's own size math exactly.
    let raw = minio_client(&minio_endpoint);
    let stored = raw
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .expect("direct MinIO get");
    assert_eq!(
        stored
            .metadata()
            .and_then(|m| m.get("s3a-v"))
            .map(String::as_str),
        Some("1"),
        "stored object must carry v1 metadata"
    );
    let stored_len = stored.content_length().unwrap() as u64;
    assert_eq!(
        stored_len,
        ciphertext_len(
            Alg::Aes256Gcm,
            plaintext.len() as u64,
            u64::from(TEST_CHUNK_SIZE)
        )
    );
    let stored_bytes = stored.body.collect().await.unwrap().into_bytes();
    assert_ne!(
        stored_bytes.as_ref(),
        plaintext.as_slice(),
        "the backend must never see plaintext"
    );
}

/// Adversarial: a client forges the proxy's own reserved
/// `x-amz-meta-s3a-*` bookkeeping keys on a plain PutObject —
/// `s3a-mp: 1` would route every later GET/HEAD into the multipart-footer
/// branch, `s3a-v: 99` would make it look like an unknown future format
/// version — hoping to make the object it just wrote unreadable through
/// the proxy, or worse, smuggle a value into `ObjectMeta::from_map`. Both
/// must be stripped by the shared write-path strip point
/// (`proxy::headers::strip_for_backend`) before the real `s3a-*` keys are
/// written, so the object round-trips exactly as if the client never sent
/// them.
#[tokio::test]
async fn forged_s3armor_metadata_on_put_is_stripped_not_stored() {
    let (client, _endpoint, minio_endpoint, _minio) = setup().await;
    let bucket = "forged-metadata";
    let key = "poisoned.bin";
    let plaintext = b"attempted metadata poisoning".to_vec();

    client
        .create_bucket()
        .bucket(bucket)
        .send()
        .await
        .expect("create bucket");
    client
        .put_object()
        .bucket(bucket)
        .key(key)
        .metadata("s3a-mp", "1")
        .metadata("s3a-v", "99")
        .metadata("s3a-kid", "not-a-real-key-id")
        .body(ByteStream::from(plaintext.clone()))
        .send()
        .await
        .expect("put object with forged s3armor metadata");

    // The object must stay fully readable — a forged s3a-mp: 1 that
    // survived would route this GET into the multipart-footer branch and
    // fail the whole request with a 502, not just leak a stray header.
    let got = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .expect("get object after forged-metadata put");
    let bytes = got.body.collect().await.unwrap().into_bytes();
    assert_eq!(bytes.as_ref(), plaintext.as_slice());

    // And the real stored metadata is this proxy's own, not the client's
    // forged values.
    let raw = minio_client(&minio_endpoint);
    let stored = raw
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .expect("direct MinIO get");
    let metadata = stored.metadata().cloned().unwrap_or_default();
    assert_eq!(
        metadata.get("s3a-v").map(String::as_str),
        Some("1"),
        "s3a-v must be this proxy's real format version, not the forged 99"
    );
    assert_ne!(
        metadata.get("s3a-kid").map(String::as_str),
        Some("not-a-real-key-id"),
        "s3a-kid must be this proxy's real active key id, not the forged value"
    );
    assert!(
        !metadata.contains_key("s3a-mp"),
        "a single-part PUT must never carry s3a-mp"
    );
}

#[tokio::test]
async fn xchacha20_round_trip_matches_the_aes_path() {
    // `setup_with`'s own doc comment names this override as its reason to
    // exist (see above) — the CPU-autoselected algorithm on an AES-NI-less
    // host, so it needs the same proof the default AES path already has:
    // byte-exact round trip, correct plaintext sizes, and ranged GET.
    let (client, _endpoint, minio_endpoint, _minio) =
        setup_with(|cfg| cfg.alg = Alg::XChaCha20Poly1305).await;
    let bucket = "xchacha20-roundtrip";
    let key = "a dir/café.txt";
    let plaintext: Vec<u8> = (0..200_000u32).map(|i| (i % 256) as u8).collect();

    client
        .create_bucket()
        .bucket(bucket)
        .send()
        .await
        .expect("create bucket");
    client
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(ByteStream::from(plaintext.clone()))
        .send()
        .await
        .expect("put object");

    let got = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .expect("get object");
    assert_eq!(
        got.content_length(),
        Some(plaintext.len() as i64),
        "GET Content-Length must be the plaintext length, not the ciphertext length"
    );
    let bytes = got.body.collect().await.unwrap().into_bytes();
    assert_eq!(bytes.as_ref(), plaintext.as_slice());

    let head = client
        .head_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .expect("head object");
    assert_eq!(head.content_length(), Some(plaintext.len() as i64));

    let ranged = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .range("bytes=65530-65540") // spans the chunk boundary
        .send()
        .await
        .expect("ranged get");
    assert!(
        ranged.content_range().is_some(),
        "206 response must carry Content-Range"
    );
    let ranged_bytes = ranged.body.collect().await.unwrap().into_bytes();
    assert_eq!(ranged_bytes.as_ref(), &plaintext[65_530..65_541]);

    // At rest, straight against MinIO: ciphertext, v1 metadata, and the
    // stored size matches the format's own size math for this algorithm.
    let raw = minio_client(&minio_endpoint);
    let stored = raw
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .expect("direct MinIO get");
    assert_eq!(
        stored
            .metadata()
            .and_then(|m| m.get("s3a-v"))
            .map(String::as_str),
        Some("1"),
        "stored object must carry v1 metadata"
    );
    let stored_len = stored.content_length().unwrap() as u64;
    assert_eq!(
        stored_len,
        ciphertext_len(
            Alg::XChaCha20Poly1305,
            plaintext.len() as u64,
            u64::from(TEST_CHUNK_SIZE)
        )
    );
    let stored_bytes = stored.body.collect().await.unwrap().into_bytes();
    assert_ne!(
        stored_bytes.as_ref(),
        plaintext.as_slice(),
        "the backend must never see plaintext"
    );
}

/// Builds an RSA-active keyring for a test: `full` also holds the private
/// key (read/full node); otherwise only the public half is configured
/// (write-only node — `docs/ARCHITECTURE.md` "Keys and wrap", "Write-only (RSA) nodes cannot serve GETs"). 2048 bits, not the
/// production default of 4096 — key generation speed only, the wrap/unwrap
/// logic under test doesn't depend on modulus size.
fn rsa_active_config(full: bool) -> impl FnOnce(&mut Config) {
    move |config: &mut Config| {
        let rsa = s3armor_format::v1::RsaKek::generate(2048).expect("generate test RSA keypair");
        let rsa = if full {
            rsa
        } else {
            let public_pem = rsa.public_pem().unwrap();
            s3armor_format::v1::RsaKek::from_public_pem(&public_pem).unwrap()
        };
        config.keyring = Keyring::new(
            s3armor::keys::RSA_ACTIVE_NAME,
            std::collections::BTreeMap::default(),
            Some(rsa),
        )
        .expect("RSA-active keyring resolves");
        config.key_active_name = s3armor::keys::RSA_ACTIVE_NAME.to_string();
    }
}

#[tokio::test]
async fn rsa_full_node_put_get_head_round_trips() {
    let (client, _endpoint, _minio_endpoint, _minio) = setup_with(rsa_active_config(true)).await;
    let bucket = "rsa-full-node";
    let key = "rsa-object.bin";
    let plaintext: Vec<u8> = (0..200_000u32).map(|i| (i % 256) as u8).collect();

    client.create_bucket().bucket(bucket).send().await.unwrap();
    client
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(ByteStream::from(plaintext.clone()))
        .send()
        .await
        .expect("put object under the active RSA key");

    let got = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .expect("get object back through the RSA private key");
    let bytes = got.body.collect().await.unwrap().into_bytes();
    assert_eq!(bytes.as_ref(), plaintext.as_slice());

    let head = client
        .head_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .unwrap();
    assert_eq!(head.content_length(), Some(plaintext.len() as i64));
}

#[tokio::test]
async fn rsa_write_only_node_puts_but_get_returns_key_not_available() {
    let (client, _endpoint, _minio_endpoint, _minio) = setup_with(rsa_active_config(false)).await;
    let bucket = "rsa-write-only-node";
    let key = "rsa-object.bin";

    client.create_bucket().bucket(bucket).send().await.unwrap();
    client
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(ByteStream::from(
            b"write-only nodes can still encrypt".to_vec(),
        ))
        .send()
        .await
        .expect("a write-only node can still PUT (wrap DEKs with the public key)");

    let err = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .expect_err("a write-only node has no private key to unwrap the DEK with");
    // `Display` on an unmodeled SDK error is just "service error" — assert
    // on `Debug`, which carries the raw HTTP status and XML error code.
    let msg = format!("{err:?}");
    assert!(
        msg.contains("503") && msg.contains("KeyNotAvailable"),
        "expected a 503 KeyNotAvailable response, got {msg}"
    );
}

#[tokio::test]
async fn ranged_get_decrypts_the_exact_plaintext_slice() {
    let (client, _endpoint, _minio_endpoint, _minio) = setup().await;
    let bucket = "ranged-get-decrypt";
    let key = "obj.bin";
    // Several chunks, so ranges can land mid-object and cross a boundary.
    let plaintext: Vec<u8> = (0..500_000u32).map(|i| (i % 256) as u8).collect();

    client
        .create_bucket()
        .bucket(bucket)
        .send()
        .await
        .expect("create bucket");
    client
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(ByteStream::from(plaintext.clone()))
        .send()
        .await
        .expect("put object");

    let cases: &[(&str, std::ops::Range<usize>)] = &[
        ("bytes=0-0", 0..1),                       // first byte
        ("bytes=499999-499999", 499_999..500_000), // last byte
        ("bytes=65530-65540", 65_530..65_541),     // spans the chunk boundary
        ("bytes=0-499999", 0..500_000),            // whole object via Range
    ];
    for (range, want) in cases {
        let resp = client
            .get_object()
            .bucket(bucket)
            .key(key)
            .range(*range)
            .send()
            .await
            .unwrap_or_else(|e| panic!("ranged get {range}: {e:?}"));
        assert!(
            resp.content_range().is_some(),
            "{range}: 206 response must carry Content-Range"
        );
        let bytes = resp.body.collect().await.unwrap().into_bytes();
        assert_eq!(bytes.as_ref(), &plaintext[want.clone()], "range {range}");
    }
}

#[tokio::test]
async fn content_md5_gives_a_plaintext_etag_shared_by_put_head_and_get() {
    let (client, _endpoint, _minio_endpoint, _minio) = setup().await;
    let bucket = "content-md5-etag";
    let key = "checked.bin";
    let body = b"the quick brown fox jumps over the lazy dog";
    let digest = <md5::Md5 as md5::Digest>::digest(body);
    let md5_b64 = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(digest)
    };
    let want_etag = format!("\"{}\"", hex::encode(digest));

    client
        .create_bucket()
        .bucket(bucket)
        .send()
        .await
        .expect("create bucket");

    let put = client
        .put_object()
        .bucket(bucket)
        .key(key)
        .content_md5(md5_b64)
        .body(ByteStream::from_static(body))
        .send()
        .await
        .expect("put with content-md5");
    assert_eq!(put.e_tag().map(str::to_string), Some(want_etag.clone()));

    let head = client
        .head_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .expect("head object");
    assert_eq!(head.e_tag().map(str::to_string), Some(want_etag.clone()));

    let got = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .expect("get object");
    assert_eq!(got.e_tag().map(str::to_string), Some(want_etag));
}

#[tokio::test]
async fn without_content_md5_put_head_and_get_agree_on_the_ciphertext_etag() {
    let (client, _endpoint, _minio_endpoint, _minio) = setup().await;
    let bucket = "no-md5-ciphertext-etag";
    let key = "unchecked.bin";
    let body = b"no content-md5 was sent for this one";

    client
        .create_bucket()
        .bucket(bucket)
        .send()
        .await
        .expect("create bucket");

    let put = client
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(ByteStream::from_static(body))
        .send()
        .await
        .expect("put object");
    let put_etag = put.e_tag().map(str::to_string);
    assert!(put_etag.is_some());

    let head = client
        .head_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .expect("head object");
    let got = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .expect("get object");

    assert_eq!(head.e_tag().map(str::to_string), put_etag);
    assert_eq!(got.e_tag().map(str::to_string), put_etag);
}

#[tokio::test]
async fn wrong_content_md5_aborts_the_put_and_leaves_no_object() {
    let (client, _endpoint, _minio_endpoint, _minio) = setup().await;
    let bucket = "bad-md5-aborts-put";
    let key = "aborted.bin";
    let body = b"this body does not match the declared md5";
    // A valid base64-of-16-bytes value, but not this body's MD5.
    let wrong_md5 = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode([0u8; 16])
    };

    client
        .create_bucket()
        .bucket(bucket)
        .send()
        .await
        .expect("create bucket");

    let err = client
        .put_object()
        .bucket(bucket)
        .key(key)
        .content_md5(wrong_md5)
        .body(ByteStream::from_static(body))
        .send()
        .await
        .expect_err("a wrong Content-MD5 must abort the PUT");
    // The client's own bytes failed verification, so this is a permanent
    // `400 BadDigest`, never the `502` a gateway failure would get — an SDK
    // retries a 502 and would replay a PUT that can never succeed.
    assert_eq!(raw_status(&err), 400);
    assert_eq!(error_code(&err).as_deref(), Some("BadDigest"));

    let listed = client
        .list_objects_v2()
        .bucket(bucket)
        .send()
        .await
        .expect("list objects");
    assert_eq!(
        listed.contents().len(),
        0,
        "no object must be left behind after an aborted PUT"
    );
}

/// A client that disconnects mid-PUT (declares a
/// `Content-Length` it never finishes sending, then closes the connection)
/// must leave no object behind. This is the `proxy/body.rs` module doc
/// comment's central claim — "both reject a tampered body before forwarding
/// completes, by ending the outbound body stream with an `Err` frame
/// instead of a clean EOF" — encoded as a test rather than left as a
/// comment. Drives the proxy over a raw TCP connection (not the SDK, which
/// would refuse to send a request it knows is short) with a hand-signed
/// SigV4 header, `s3armor::sigv4::sign::authorization_header` — the same helper
/// `tools::bench`'s proxy-mode client uses to authenticate against a
/// running proxy.
#[tokio::test]
async fn client_disconnect_mid_put_leaves_no_object() {
    let (client, endpoint, _minio_endpoint, _minio) = setup().await;
    let bucket = "client-disconnect-mid-put";
    let key = "aborted-upload.bin";
    client
        .create_bucket()
        .bucket(bucket)
        .send()
        .await
        .expect("create bucket");

    let host = endpoint
        .strip_prefix("http://")
        .expect("proxy endpoint is http://host:port");
    let amz_date = s3armor::sigv4::time::format_amz_date(std::time::SystemTime::now());
    let path = format!("/{bucket}/{key}");
    let headers = vec![
        ("host".to_string(), host.to_string()),
        ("x-amz-date".to_string(), amz_date.clone()),
    ];
    let signed_names = vec!["host".to_string(), "x-amz-date".to_string()];
    let auth = s3armor::sigv4::sign::authorization_header(
        "PUT",
        &path,
        "",
        &headers,
        &signed_names,
        "UNSIGNED-PAYLOAD",
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
        "us-east-1",
        "s3",
        &amz_date,
    );

    // Declares 1000 bytes of body, sends 10, then drops the connection —
    // never writes the rest and never sends a clean EOF.
    let declared_len = 1000;
    let sent_body = vec![0x42u8; 10];
    let request = format!(
        "PUT {path} HTTP/1.1\r\n\
         host: {host}\r\n\
         x-amz-date: {amz_date}\r\n\
         authorization: {auth}\r\n\
         content-length: {declared_len}\r\n\
         connection: close\r\n\
         \r\n"
    );

    let mut stream = TcpStream::connect(host)
        .await
        .expect("connect to the proxy");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request headers");
    stream
        .write_all(&sent_body)
        .await
        .expect("write partial body");
    drop(stream); // disconnect without sending the remaining 990 bytes

    // Give the proxy a moment to notice the aborted read and unwind.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let listed = client
        .list_objects_v2()
        .bucket(bucket)
        .send()
        .await
        .expect("list objects");
    assert_eq!(
        listed.contents().len(),
        0,
        "a client that disconnects mid-PUT must leave no object behind"
    );
}

/// A signed `x-amz-content-sha256` that does not match the bytes that
/// follow it must fail as `400 XAmzContentSHA256Mismatch`, the same as real
/// S3 — not the `502` this used to report, which tells an SDK to retry a
/// PUT that can never succeed. The SDK never sends a payload hash it did
/// not compute itself, so this is hand-signed over a raw request, like
/// `client_disconnect_mid_put_leaves_no_object` above.
#[tokio::test]
async fn wrong_payload_hash_is_rejected_as_a_client_error() {
    let (client, endpoint, _minio_endpoint, _minio) = setup().await;
    let bucket = "bad-payload-hash";
    let key = "mismatched.bin";
    client
        .create_bucket()
        .bucket(bucket)
        .send()
        .await
        .expect("create bucket");

    let host = endpoint
        .strip_prefix("http://")
        .expect("proxy endpoint is http://host:port");
    let amz_date = s3armor::sigv4::time::format_amz_date(std::time::SystemTime::now());
    let path = format!("/{bucket}/{key}");
    // The hash of a body that is not the one sent below.
    let payload_hash = s3armor::sigv4::canonical::hex_sha256(b"the body the client promised");
    let headers = vec![
        ("host".to_string(), host.to_string()),
        ("x-amz-content-sha256".to_string(), payload_hash.clone()),
        ("x-amz-date".to_string(), amz_date.clone()),
    ];
    let signed_names = vec![
        "host".to_string(),
        "x-amz-content-sha256".to_string(),
        "x-amz-date".to_string(),
    ];
    let auth = s3armor::sigv4::sign::authorization_header(
        "PUT",
        &path,
        "",
        &headers,
        &signed_names,
        &payload_hash,
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
        "us-east-1",
        "s3",
        &amz_date,
    );

    let req = http::Request::builder()
        .method("PUT")
        .uri(format!("{endpoint}{path}"))
        .header("x-amz-date", &amz_date)
        .header("authorization", &auth)
        .header("x-amz-content-sha256", &payload_hash)
        .body(http_body_util::Full::new(bytes::Bytes::from_static(
            b"the body the client actually sent",
        )))
        .expect("build PUT request");
    let http_client: hyper_util::client::legacy::Client<_, http_body_util::Full<bytes::Bytes>> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();
    let resp = http_client
        .request(req)
        .await
        .expect("PUT reaches the proxy");
    let status = resp.status();
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .expect("read the error body")
        .to_bytes();
    let xml = String::from_utf8_lossy(&body);
    assert_eq!(status, 400, "a payload-hash mismatch is a 400: {xml}");
    assert!(
        xml.contains("<Code>XAmzContentSHA256Mismatch</Code>"),
        "expected XAmzContentSHA256Mismatch, got {xml}"
    );

    let listed = client
        .list_objects_v2()
        .bucket(bucket)
        .send()
        .await
        .expect("list objects");
    assert_eq!(
        listed.contents().len(),
        0,
        "no object must be left behind after a rejected PUT"
    );
}

/// `x-amz-decoded-content-length` is trusted verbatim as the plaintext
/// length for, on multipart, the persisted `PartRecord.pt_len`
/// (`intercept::mpu::handle_upload_part`) — but was never itself checked
/// against the real aws-chunked payload (`S3ARMOR-REVIEW.md` §1.3). This
/// targets the small-part buffered branch specifically: unlike the
/// streaming branch, its outbound `Content-Length` is derived from the
/// real encrypted bytes (`ct.len()`), not the client's declared length, so
/// no transport-level Content-Length check catches a lie here — only the
/// explicit `plaintext.len() != pt_len` check added in `intercept::mpu`
/// does. A declared length that disagrees with the real body must abort
/// the part upload rather than silently recording the wrong `pt_len` (the
/// exact case that used to desync a sealed footer's part layout from the
/// real ciphertext, per the review). Hand-signed like
/// `client_disconnect_mid_put_leaves_no_object` above, since the SDK always
/// computes a correct decoded length itself.
#[tokio::test]
async fn upload_part_decoded_length_mismatch_is_rejected() {
    let (client, endpoint, _minio_endpoint, _minio) = setup().await;
    let bucket = "upload-part-length-mismatch";
    let key = "lied-length.bin";
    client
        .create_bucket()
        .bucket(bucket)
        .send()
        .await
        .expect("create bucket");
    let created = client
        .create_multipart_upload()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .expect("create multipart upload");
    let upload_id = created.upload_id().expect("upload id").to_string();

    let host = endpoint
        .strip_prefix("http://")
        .expect("proxy endpoint is http://host:port");
    let amz_date = s3armor::sigv4::time::format_amz_date(std::time::SystemTime::now());
    let path = format!("/{bucket}/{key}");
    let raw_query = format!("partNumber=1&uploadId={upload_id}");
    let payload_hash = "STREAMING-UNSIGNED-PAYLOAD-TRAILER";
    let headers = vec![
        ("host".to_string(), host.to_string()),
        ("x-amz-date".to_string(), amz_date.clone()),
    ];
    let signed_names = vec!["host".to_string(), "x-amz-date".to_string()];
    let auth = s3armor::sigv4::sign::authorization_header(
        "PUT",
        &path,
        &raw_query,
        &headers,
        &signed_names,
        payload_hash,
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
        "us-east-1",
        "s3",
        &amz_date,
    );

    // A real 11-byte plaintext as a single unsigned chunk, small enough
    // that `handle_upload_part` picks the buffered small-part branch
    // regardless — but `x-amz-decoded-content-length` overstates it as
    // 999. (The understating direction is separately caught by `Limited`
    // capping the buffer at the declared length; this direction only the
    // explicit `plaintext.len() != pt_len` check catches.)
    let plaintext = b"hello world";
    let mut wire = format!("{:x}\r\n", plaintext.len()).into_bytes();
    wire.extend_from_slice(plaintext);
    wire.extend_from_slice(b"\r\n0\r\n\r\n");

    let req = http::Request::builder()
        .method("PUT")
        .uri(format!("{endpoint}{path}?{raw_query}"))
        .header("x-amz-date", &amz_date)
        .header("authorization", &auth)
        .header("x-amz-content-sha256", payload_hash)
        .header("x-amz-decoded-content-length", "999")
        .body(http_body_util::Full::new(bytes::Bytes::from(wire)))
        .expect("build UploadPart request");
    let http_client: hyper_util::client::legacy::Client<_, http_body_util::Full<bytes::Bytes>> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();
    let resp = http_client
        .request(req)
        .await
        .expect("UploadPart reaches the proxy");
    assert!(
        !resp.status().is_success(),
        "a declared decoded length that disagrees with the real body must be rejected, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn corrupted_ciphertext_at_rest_is_rejected_on_get() {
    let (client, _endpoint, minio_endpoint, _minio) = setup().await;
    let bucket = "corrupted-ciphertext-rejected";
    let key = "tampered.bin";
    let plaintext = b"integrity matters even when nobody is watching";

    client
        .create_bucket()
        .bucket(bucket)
        .send()
        .await
        .expect("create bucket");
    client
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(ByteStream::from_static(plaintext))
        .send()
        .await
        .expect("put object");

    // Flip a byte in the stored ciphertext directly against MinIO, bypassing
    // the proxy — this is the "an attacker with backend write access
    // tampers with an object" threat the AEAD tag exists for.
    let raw = minio_client(&minio_endpoint);
    let stored = raw
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .expect("direct MinIO get");
    let headers_meta = stored.metadata().cloned();
    let mut ciphertext = stored.body.collect().await.unwrap().into_bytes().to_vec();
    ciphertext[0] ^= 0x01;

    let mut put_req = raw
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(ByteStream::from(ciphertext));
    if let Some(meta) = headers_meta {
        for (k, v) in meta {
            put_req = put_req.metadata(k, v);
        }
    }
    put_req
        .send()
        .await
        .expect("overwrite with corrupted ciphertext");

    // The declared Content-Length goes out with the response headers before
    // any chunk is verified, so a tampered object can still get an `Ok`
    // here — the corruption must surface when the body is actually read
    // (a truncated/aborted stream), not necessarily as a `send()` error.
    //
    // A completed `Ok(collected)` is never an acceptable
    // outcome, tampered or not — the streaming decoder provably releases
    // nothing from a corrupted frame
    // (`s3armor-format/tests/corruption.rs::streaming_decoder_releases_nothing_from_a_corrupted_frame`),
    // so a 200 that finishes streaming here would itself be the bug, not a
    // second-best case to tolerate with a weaker assertion.
    let result = client.get_object().bucket(bucket).key(key).send().await;
    match result {
        Err(_) => {} // rejected before headers were even returned
        Ok(resp) => {
            let body_result = resp.body.collect().await;
            assert!(
                body_result.is_err(),
                "a corrupted object must never stream out as a completed response"
            );
        }
    }
}

/// Writes `a` and `b`, then overwrites `b`'s ciphertext *and* metadata with
/// `a`'s directly against MinIO — the object-swap attack `docs/ARCHITECTURE.md`
/// "Path binding" describes (an attacker with backend write access, not a client of
/// the proxy). Returns `a`'s plaintext, for the caller to compare against
/// what GETting `b` now returns.
async fn swap_objects(client: &Client, minio_endpoint: &str, bucket: &str) -> Vec<u8> {
    let plaintext_a = b"object a's real content".to_vec();
    let plaintext_b = b"object b's real content, soon overwritten".to_vec();

    client.create_bucket().bucket(bucket).send().await.unwrap();
    client
        .put_object()
        .bucket(bucket)
        .key("a")
        .body(ByteStream::from(plaintext_a.clone()))
        .send()
        .await
        .expect("put a");
    client
        .put_object()
        .bucket(bucket)
        .key("b")
        .body(ByteStream::from(plaintext_b))
        .send()
        .await
        .expect("put b");

    let raw = minio_client(minio_endpoint);
    let stored_a = raw
        .get_object()
        .bucket(bucket)
        .key("a")
        .send()
        .await
        .expect("direct MinIO get of a");
    let meta_a = stored_a.metadata().cloned();
    let ciphertext_a = stored_a.body.collect().await.unwrap().into_bytes().to_vec();

    let mut put_req = raw
        .put_object()
        .bucket(bucket)
        .key("b")
        .body(ByteStream::from(ciphertext_a));
    if let Some(meta) = meta_a {
        for (k, v) in meta {
            put_req = put_req.metadata(k, v);
        }
    }
    put_req
        .send()
        .await
        .expect("overwrite b with a's ciphertext+metadata");

    plaintext_a
}

#[tokio::test]
async fn object_swap_attack_succeeds_silently_under_bind_paths_off() {
    let (client, _endpoint, minio_endpoint, _minio) =
        setup_with(|cfg| cfg.bind_mode = BindMode::Off).await;
    let bucket = "swap-attack-bind-off";
    let plaintext_a = swap_objects(&client, &minio_endpoint, bucket).await;

    // b's wrapped DEK carries no path binding under `off` — nothing stops
    // it from decrypting a's ciphertext, so GET b silently returns a's
    // content. This is the documented risk `S3A_BIND_PATHS` exists to
    // close, not a bug in this test.
    let got = client
        .get_object()
        .bucket(bucket)
        .key("b")
        .send()
        .await
        .expect("get b")
        .body
        .collect()
        .await
        .expect("b's ciphertext, now really a's, still authenticates under a's own DEK")
        .into_bytes()
        .to_vec();
    assert_eq!(got, plaintext_a, "under off, the swap succeeds silently");
}

#[tokio::test]
async fn object_swap_attack_is_detected_under_bind_paths_on() {
    let (client, _endpoint, minio_endpoint, _minio) =
        setup_with(|cfg| cfg.bind_mode = BindMode::On).await;
    let bucket = "swap-attack-bind-on";
    swap_objects(&client, &minio_endpoint, bucket).await;

    // a's wrapped DEK is bound to "bucket ‖ a"; served at "b" it fails both
    // the bound and (on `on`'s fallback) the empty-binding unwrap attempt.
    let err = client
        .get_object()
        .bucket(bucket)
        .key("b")
        .send()
        .await
        .expect_err("the swap must be detected, not silently served");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("403") && msg.contains("AccessDenied"),
        "expected a 403 AccessDenied response, got {msg}"
    );
}

#[tokio::test]
async fn bind_paths_on_still_reads_an_object_written_under_off() {
    let bucket = "bind-on-reads-off-written";
    let key = "pre-existing.bin";
    let plaintext = b"written before S3A_BIND_PATHS existed";

    // Write under `off`, then start a *second* proxy against the same
    // MinIO container with `on` — mirroring an operator flipping the env
    // var and restarting the proxy without touching any existing object.
    let (client_off, _endpoint, minio_endpoint, _minio) =
        setup_with(|cfg| cfg.bind_mode = BindMode::Off).await;
    client_off
        .create_bucket()
        .bucket(bucket)
        .send()
        .await
        .unwrap();
    client_off
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(ByteStream::from_static(plaintext))
        .send()
        .await
        .expect("put under off");

    let (client_on, _endpoint2) =
        spawn_proxy(&minio_endpoint, |cfg| cfg.bind_mode = BindMode::On).await;
    let got = client_on
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .expect("an object written under off must still read under on")
        .body
        .collect()
        .await
        .expect("body")
        .into_bytes()
        .to_vec();
    assert_eq!(got, plaintext);
}

/// `strict` is the retirement switch — its entire promise is that an
/// unbound object is *rejected*, not silently served. Originally no test
/// exercised `strict` at all.
#[tokio::test]
async fn bind_paths_strict_rejects_an_object_written_under_off() {
    let bucket = "strict-rejects-off-written";
    let key = "unbound.bin";
    let plaintext = b"written before S3A_BIND_PATHS=strict was ever set";

    let (client_off, _endpoint, minio_endpoint, _minio) =
        setup_with(|cfg| cfg.bind_mode = BindMode::Off).await;
    client_off
        .create_bucket()
        .bucket(bucket)
        .send()
        .await
        .expect("create bucket");
    client_off
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(ByteStream::from_static(plaintext))
        .send()
        .await
        .expect("put under off");

    let (client_strict, _endpoint2) =
        spawn_proxy(&minio_endpoint, |cfg| cfg.bind_mode = BindMode::Strict).await;
    let err = client_strict
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .expect_err("strict must reject an unbound object, not serve it");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("403") && msg.contains("AccessDenied"),
        "expected a 403 AccessDenied response, got {msg}"
    );
}

/// The other half of `strict`: an object actually written under `strict`
/// (bound, unwrap-bound-only) must read back normally through it — the
/// mode is not simply "always fail".
#[tokio::test]
async fn bind_paths_strict_reads_an_object_written_under_strict() {
    let (client, _endpoint, _minio_endpoint, _minio) =
        setup_with(|cfg| cfg.bind_mode = BindMode::Strict).await;
    let bucket = "strict-roundtrip";
    let key = "bound.bin";
    let plaintext = b"written and read entirely under strict";

    client
        .create_bucket()
        .bucket(bucket)
        .send()
        .await
        .expect("create bucket");
    client
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(ByteStream::from_static(plaintext))
        .send()
        .await
        .expect("put under strict");

    let got = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .expect("an object written under strict must read back under strict")
        .body
        .collect()
        .await
        .expect("body")
        .into_bytes()
        .to_vec();
    assert_eq!(got, plaintext);
}

/// `s3armor rebind` is the documented path from an unbound object to a
/// `strict`-readable one (`docs/ARCHITECTURE.md` "Path binding") — originally
/// untested. Writes under `off`, confirms `strict` rejects it
/// (same defect as the test above), rebinds, then confirms `strict` now
/// reads it.
#[tokio::test]
async fn rebind_makes_an_off_written_object_readable_under_strict() {
    let bucket = "rebind-off-to-strict";
    let key = "to-rebind.bin";
    let plaintext = b"rebind me into strict";

    let (client_off, _endpoint, minio_endpoint, _minio) =
        setup_with(|cfg| cfg.bind_mode = BindMode::Off).await;
    client_off
        .create_bucket()
        .bucket(bucket)
        .send()
        .await
        .expect("create bucket");
    client_off
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(ByteStream::from_static(plaintext))
        .send()
        .await
        .expect("put under off");

    let (client_strict, _endpoint2, state_strict) =
        spawn_proxy_with_state(&minio_endpoint, |cfg| cfg.bind_mode = BindMode::Strict).await;

    client_strict
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .expect_err("must still be rejected before rebind");

    let report = s3armor::tools::rewrap::rebind(
        state_strict.clone(),
        s3armor::tools::rewrap::RebindArgs {
            bucket: bucket.to_string(),
            ..Default::default()
        },
    )
    .await
    .expect("rebind must run");
    assert_eq!(report.rebound, 1, "exactly one object was unbound");
    assert!(report.ok(), "rebind must not fail: {report:?}");

    let got = client_strict
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .expect("rebound object must now read under strict")
        .body
        .collect()
        .await
        .expect("body")
        .into_bytes()
        .to_vec();
    assert_eq!(got, plaintext);
}

/// Full multipart coverage — retried/duplicate/out-of-order parts, retried
/// Complete, ranges across a part boundary — lives in
/// `tests/integration_mpu.rs`. This is only a smoke check that this file's
/// own setup can drive a basic multipart round-trip too.
#[tokio::test]
async fn multipart_create_upload_complete_round_trips() {
    let (client, _endpoint, _minio_endpoint, _minio) = setup().await;
    let bucket = "multipart-crypto-roundtrip";
    let key = "big-upload.bin";

    client
        .create_bucket()
        .bucket(bucket)
        .send()
        .await
        .expect("create bucket");

    let upload_id = client
        .create_multipart_upload()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .expect("create multipart upload")
        .upload_id()
        .expect("upload id")
        .to_string();

    let part_data = vec![0xABu8; 6 * 1024 * 1024];
    let etag = client
        .upload_part()
        .bucket(bucket)
        .key(key)
        .upload_id(&upload_id)
        .part_number(1)
        .body(ByteStream::from(part_data.clone()))
        .send()
        .await
        .expect("upload part")
        .e_tag()
        .expect("part etag")
        .to_string();

    client
        .complete_multipart_upload()
        .bucket(bucket)
        .key(key)
        .upload_id(&upload_id)
        .multipart_upload(
            CompletedMultipartUpload::builder()
                .parts(CompletedPart::builder().part_number(1).e_tag(etag).build())
                .build(),
        )
        .send()
        .await
        .expect("complete multipart upload");

    let got = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .expect("get object")
        .body
        .collect()
        .await
        .expect("collect body")
        .into_bytes();
    assert_eq!(got.as_ref(), part_data.as_slice());
}

/// The same ±1-byte boundary lengths `s3armor-format`'s
/// `tests/boundaries.rs` checks against the codec directly, driven through
/// the whole proxy — proves the size math survives the proxy's own
/// `Content-Length` precomputation (`intercept::put`'s `ciphertext_len`
/// call before the body streams), not just the codec in isolation.
#[tokio::test]
async fn size_ladder_round_trips_at_every_chunk_boundary() {
    let (client, _endpoint, _minio_endpoint, _minio) = setup().await;
    let bucket = "size-ladder-chunk-boundaries";
    client
        .create_bucket()
        .bucket(bucket)
        .send()
        .await
        .expect("create bucket");

    let chunk = u64::from(TEST_CHUNK_SIZE);
    let lengths = [0u64, 1, chunk - 1, chunk, chunk + 1];
    for pt_len in lengths {
        let key = format!("obj-{pt_len}.bin");
        let plaintext: Vec<u8> = (0..pt_len).map(|i| (i % 256) as u8).collect();

        client
            .put_object()
            .bucket(bucket)
            .key(&key)
            .body(ByteStream::from(plaintext.clone()))
            .send()
            .await
            .unwrap_or_else(|e| panic!("put pt_len={pt_len}: {e:?}"));

        let head = client
            .head_object()
            .bucket(bucket)
            .key(&key)
            .send()
            .await
            .unwrap_or_else(|e| panic!("head pt_len={pt_len}: {e:?}"));
        assert_eq!(
            head.content_length(),
            Some(pt_len as i64),
            "HEAD content-length at pt_len={pt_len}"
        );

        let got = client
            .get_object()
            .bucket(bucket)
            .key(&key)
            .send()
            .await
            .unwrap_or_else(|e| panic!("get pt_len={pt_len}: {e:?}"))
            .body
            .collect()
            .await
            .expect("collect body")
            .into_bytes();
        assert_eq!(got.as_ref(), plaintext.as_slice(), "GET at pt_len={pt_len}");

        if pt_len > chunk {
            // A range straddling the chunk boundary — only meaningful once
            // the object has more than one chunk.
            let resp = client
                .get_object()
                .bucket(bucket)
                .key(&key)
                .range(format!("bytes={}-{}", chunk - 1, chunk))
                .send()
                .await
                .unwrap_or_else(|e| panic!("ranged get pt_len={pt_len}: {e:?}"));
            let bytes = resp.body.collect().await.unwrap().into_bytes();
            assert_eq!(
                bytes.as_ref(),
                &plaintext[(chunk - 1) as usize..=(chunk as usize)],
                "ranged get at pt_len={pt_len}"
            );
        }
    }
}

/// `SelectObjectContent` is explicitly unsupported in v1: the backend would
/// run the SQL expression over ciphertext, not plaintext. MinIO itself
/// implements Select, so before the fix this request reaches MinIO and
/// gets MinIO's own parse error (or an empty/wrong result) over ciphertext
/// — a wrong answer dressed up as a client error. This test has teeth: it
/// fails before the routing fix (MinIO's error, not the proxy's) and
/// passes after (the proxy's honest 501, body never even read).
#[tokio::test]
async fn select_object_content_is_not_implemented() {
    let (client, _endpoint, _minio_endpoint, _minio) = setup().await;
    let bucket = "select-not-implemented";
    let key = "data.csv";

    client
        .create_bucket()
        .bucket(bucket)
        .send()
        .await
        .expect("create bucket");
    client
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(ByteStream::from_static(b"a,b,c\n1,2,3\n"))
        .send()
        .await
        .expect("put csv-shaped object");

    let err = client
        .select_object_content()
        .bucket(bucket)
        .key(key)
        .expression("SELECT * FROM S3Object")
        .expression_type(ExpressionType::Sql)
        .input_serialization(
            InputSerialization::builder()
                .csv(CsvInput::builder().build())
                .build(),
        )
        .output_serialization(
            OutputSerialization::builder()
                .csv(CsvOutput::builder().build())
                .build(),
        )
        .send()
        .await
        .expect_err("SelectObjectContent must be rejected, never run against ciphertext");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("NotImplemented") || msg.contains("501"),
        "expected an honest NotImplemented, got: {msg}"
    );
}

/// CORS preflight (`OPTIONS`) must be answered from the backend's own
/// bucket CORS configuration, and answered **before** auth — a browser
/// preflight carries no `Authorization` header by design, so requiring
/// SigV4 here would fail every real preflight with `403` before the
/// browser ever saw the backend's actual CORS answer (`docs/ARCHITECTURE.md`
/// "S3 operation matrix (v1)": "answered from the backend's bucket CORS
/// config, before auth").
#[tokio::test]
async fn cors_preflight_is_answered_before_auth() {
    let (client, endpoint, _minio_endpoint, _minio) = setup().await;
    let bucket = "cors-preflight";

    client
        .create_bucket()
        .bucket(bucket)
        .send()
        .await
        .expect("create bucket");
    // No `PutBucketCors` here — this MinIO tag doesn't implement that S3
    // API at all (`NotImplemented`, confirmed against a bare container).
    // MinIO answers every OPTIONS preflight with its own built-in
    // default-permissive CORS response regardless, which is exactly what
    // this test needs: proof the *backend's own* CORS answer comes back,
    // not the proxy's `403` for a request with no `Authorization` header.

    // A raw OPTIONS preflight, no Authorization header at all — the shape
    // a browser actually sends.
    let req = http::Request::builder()
        .method("OPTIONS")
        .uri(format!("{endpoint}/{bucket}/some-key.txt"))
        .header("Origin", "https://example.test")
        .header("Access-Control-Request-Method", "GET")
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .expect("build OPTIONS request");
    let http_client: hyper_util::client::legacy::Client<_, http_body_util::Empty<bytes::Bytes>> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();
    let resp = http_client
        .request(req)
        .await
        .expect("OPTIONS preflight reaches the proxy");
    assert!(
        resp.status().is_success(),
        "unauthenticated CORS preflight must succeed (backend's own CORS answer), got {}",
        resp.status()
    );
    assert_eq!(
        resp.headers()
            .get("access-control-allow-origin")
            .map(|v| v.to_str().unwrap_or_default()),
        Some("https://example.test"),
        "must carry the backend's own CORS answer, not a generic response"
    );
}

/// The raw HTTP status of an `SdkError`'s underlying response, for
/// asserting `304`/`412` — neither is a normal 2xx data response, so the
/// SDK surfaces both as an `Err`, but the real status is still on the wire.
/// The `<Code>` out of the S3 XML error body an `SdkError` carries — what
/// a client switches on to tell "retry this" from "this request can never
/// succeed".
fn error_code<E: std::fmt::Debug>(err: &aws_sdk_s3::error::SdkError<E>) -> Option<String> {
    let body = err.raw_response()?.body().bytes()?;
    let xml = String::from_utf8_lossy(body);
    let (_, after) = xml.split_once("<Code>")?;
    let (code, _) = after.split_once("</Code>")?;
    Some(code.to_string())
}

fn raw_status<E: std::fmt::Debug>(err: &aws_sdk_s3::error::SdkError<E>) -> u16 {
    err.raw_response().map_or_else(
        || panic!("expected an HTTP response on the error, got {err:?}"),
        |r| r.status().as_u16(),
    )
}

/// `If-Match`/`If-None-Match` must be evaluated against the
/// *plaintext* ETag this proxy hands out (`s3a-emd5`, `docs/ARCHITECTURE.md`
/// "ETag policy") — not the ciphertext ETag the backend actually stores under.
/// Before this fix there was no conditional handling at all: the header
/// reached the backend unmodified and was compared against the wrong ETag,
/// so `If-None-Match` with the proxy's own advertised ETag never produced a
/// `304` and `If-Match` with it always produced a spurious `412`.
#[tokio::test]
async fn conditional_requests_evaluate_against_the_plaintext_etag() {
    let (client, _endpoint, _minio_endpoint, _minio) = setup().await;
    let bucket = "conditional-plaintext-etag";
    let key = "checked.bin";
    let body = b"the quick brown fox jumps over the lazy dog";
    let digest = <md5::Md5 as md5::Digest>::digest(body);
    let md5_b64 = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(digest)
    };
    let etag = format!("\"{}\"", hex::encode(digest));

    client
        .create_bucket()
        .bucket(bucket)
        .send()
        .await
        .expect("create bucket");
    client
        .put_object()
        .bucket(bucket)
        .key(key)
        .content_md5(md5_b64)
        .body(ByteStream::from_static(body))
        .send()
        .await
        .expect("put with content-md5");

    // GET + If-None-Match: <plaintext etag> -> 304, no body re-sent.
    let err = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .if_none_match(&etag)
        .send()
        .await
        .expect_err("matching If-None-Match must yield 304, not 200");
    assert_eq!(raw_status(&err), 304);

    // GET + If-None-Match: "bogus" -> 200, full plaintext.
    let got = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .if_none_match("\"bogus\"")
        .send()
        .await
        .expect("non-matching If-None-Match must proceed");
    let bytes = got.body.collect().await.expect("collect body").into_bytes();
    assert_eq!(bytes.as_ref(), body);

    // GET + If-Match: <plaintext etag> -> 200, full plaintext.
    let got = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .if_match(&etag)
        .send()
        .await
        .expect("matching If-Match must proceed");
    let bytes = got.body.collect().await.expect("collect body").into_bytes();
    assert_eq!(bytes.as_ref(), body);

    // GET + If-Match: "bogus" -> 412.
    let err = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .if_match("\"bogus\"")
        .send()
        .await
        .expect_err("non-matching If-Match must yield 412, not 200");
    assert_eq!(raw_status(&err), 412);

    // HEAD + If-None-Match: <plaintext etag> -> 304.
    let err = client
        .head_object()
        .bucket(bucket)
        .key(key)
        .if_none_match(&etag)
        .send()
        .await
        .expect_err("matching If-None-Match on HEAD must yield 304");
    assert_eq!(raw_status(&err), 304);

    // A ranged GET is still subject to the whole-object conditional check
    // first — 304, never 206, matching real S3's own precedence.
    let err = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .range("bytes=0-4")
        .if_none_match(&etag)
        .send()
        .await
        .expect_err("a matching conditional must short-circuit a ranged GET too");
    assert_eq!(raw_status(&err), 304);
}

/// `x-amz-copy-source-if-match`/`-if-none-match` name the plaintext ETag
/// this proxy handed the client for the source object, same as
/// `If-Match`/`If-None-Match` on GET/HEAD — they must be translated to the
/// backend's own stored ETag before the copy is forwarded, or a matching
/// `if-match` would spuriously fail (backend compares against ciphertext)
/// and a non-matching `if-none-match` would spuriously succeed a copy the
/// client meant to skip.
#[tokio::test]
async fn copy_source_conditionals_evaluate_against_the_plaintext_etag() {
    let (client, _endpoint, _minio_endpoint, _minio) = setup().await;
    let bucket = "copy-source-conditional-etag";
    let src_key = "source.bin";
    let dst_key = "dest.bin";
    let body = b"the quick brown fox jumps over the lazy dog";
    let digest = <md5::Md5 as md5::Digest>::digest(body);
    let md5_b64 = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(digest)
    };
    let etag = format!("\"{}\"", hex::encode(digest));

    client
        .create_bucket()
        .bucket(bucket)
        .send()
        .await
        .expect("create bucket");
    client
        .put_object()
        .bucket(bucket)
        .key(src_key)
        .content_md5(md5_b64)
        .body(ByteStream::from_static(body))
        .send()
        .await
        .expect("put with content-md5");

    // Copy-source-if-match with the plaintext ETag the client was handed
    // must proceed, not 412 against the backend's ciphertext ETag.
    client
        .copy_object()
        .bucket(bucket)
        .key(dst_key)
        .copy_source(format!("{bucket}/{src_key}"))
        .copy_source_if_match(&etag)
        .send()
        .await
        .expect("copy-source-if-match on the effective ETag must proceed");
    let got = client
        .get_object()
        .bucket(bucket)
        .key(dst_key)
        .send()
        .await
        .expect("get the copy");
    let bytes = got.body.collect().await.expect("collect body").into_bytes();
    assert_eq!(bytes.as_ref(), body);

    // Copy-source-if-match with a wrong ETag must still 412.
    let err = client
        .copy_object()
        .bucket(bucket)
        .key("dest-should-not-exist.bin")
        .copy_source(format!("{bucket}/{src_key}"))
        .copy_source_if_match("\"bogus\"")
        .send()
        .await
        .expect_err("non-matching copy-source-if-match must yield 412, not succeed");
    assert_eq!(raw_status(&err), 412);

    // Copy-source-if-none-match with the plaintext ETag the client was
    // handed must be rejected — this is the direction where a client asking
    // to skip an unchanged source must not have its copy silently proceed.
    let err = client
        .copy_object()
        .bucket(bucket)
        .key("dest-should-also-not-exist.bin")
        .copy_source(format!("{bucket}/{src_key}"))
        .copy_source_if_none_match(&etag)
        .send()
        .await
        .expect_err("copy-source-if-none-match on the effective ETag must be rejected");
    assert_eq!(raw_status(&err), 412);
}

/// `If-Match: *`/`If-None-Match: *` are existence checks, not content
/// checks — this proxy leaves them for the backend to answer rather than
/// intercepting them, so they must keep working exactly as they did before
/// conditional interception existed.
#[tokio::test]
async fn star_conditional_is_unaffected_by_interception() {
    let (client, _endpoint, _minio_endpoint, _minio) = setup().await;
    let bucket = "star-conditional-unaffected";
    let key = "exists.bin";
    client
        .create_bucket()
        .bucket(bucket)
        .send()
        .await
        .expect("create bucket");
    client
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(ByteStream::from_static(b"present"))
        .send()
        .await
        .expect("put object");

    let err = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .if_none_match("*")
        .send()
        .await
        .expect_err("If-None-Match: * on an existing object must yield 304");
    assert_eq!(raw_status(&err), 304);
}

/// Regression guard: a plaintext object (no `s3a-*` metadata at all,
/// written straight to MinIO, bypassing the proxy's encryption path)
/// must see the exact same conditional behavior a real backend gives —
/// `effective_etag` falls back to the backend's own ETag for anything
/// that isn't a v1 single-part object with `s3a-emd5`.
#[tokio::test]
async fn conditional_requests_on_a_plaintext_object_match_backend_semantics() {
    let (client, _endpoint, minio_endpoint, _minio) = setup().await;
    let bucket = "conditional-plaintext-object";
    let key = "plain.txt";
    let direct = minio_client(&minio_endpoint);
    direct
        .create_bucket()
        .bucket(bucket)
        .send()
        .await
        .expect("create bucket direct on minio");
    let put = direct
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(ByteStream::from_static(
            b"plaintext, never touched by s3armor",
        ))
        .send()
        .await
        .expect("put object direct on minio");
    let etag = put.e_tag().expect("minio returns an etag").to_string();

    let err = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .if_none_match(&etag)
        .send()
        .await
        .expect_err("a plaintext object's own backend etag must still 304 through the proxy");
    assert_eq!(raw_status(&err), 304);
}

/// `S3A_TIMEOUT_CONNECT` must actually bound the dial to the backend
/// (`proxy::client::build`'s `HttpConnector::set_connect_timeout`) —
/// originally the knob was parsed and printed by `s3armor config` but
/// never consumed (AGENTS.md: "no config knob without a test exercising
/// its effect"), so a hung dial hung the proxy forever. `203.0.113.1` is
/// TEST-NET-3 (RFC 5737): reserved for documentation, so it is never a
/// live host and most networks/sandboxes silently drop packets to it
/// rather than refusing the connection — a real hung dial, not an
/// instant "connection refused". A bounded failure well under the OS's
/// own default connect timeout (30s-127s depending on platform) proves
/// the knob is wired.
#[tokio::test]
async fn backend_connect_timeout_fails_fast_instead_of_hanging() {
    let (client, _endpoint) = spawn_proxy("http://203.0.113.1:9", |config| {
        config.timeout_connect = Duration::from_millis(300);
    })
    .await;

    let start = tokio::time::Instant::now();
    let err = client
        .head_bucket()
        .bucket("whatever")
        .send()
        .await
        .expect_err("an unroutable backend must fail, not hang");
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "backend connect must fail within S3A_TIMEOUT_CONNECT, took {elapsed:?}"
    );
    // The SDK's own connection is to our proxy (loopback, healthy) — only
    // the proxy's downstream dial to 203.0.113.1 fails, so the SDK still
    // gets a normal HTTP response: the proxy's own 502 for the failed
    // backend request (`S3Error::bad_gateway`, `proxy::forward`).
    assert_eq!(raw_status(&err), 502);
}

/// `S3A_TIMEOUT_REQUEST` bounds `proxy::forward`'s wait for the
/// backend's response *headers* only — never a body already streaming
/// back to the client. Proven by pacing the client's own consumption of a
/// GET response slower than the configured timeout: if `forward` (or
/// anything downstream of it) wrapped the whole exchange in one timeout,
/// this GET would be aborted mid-stream; it must instead complete
/// normally, because by the time this sleep starts, the one `.await` the
/// timeout actually wraps has already resolved.
#[tokio::test]
async fn slow_client_body_read_is_not_bounded_by_the_backend_response_timeout() {
    let timeout_request = Duration::from_millis(200);
    let (client, _endpoint, _minio_endpoint, _minio) =
        setup_with(|config| config.timeout_request = timeout_request).await;
    let bucket = "slow-client-body-read";
    let key = "slow.bin";
    let plaintext: Vec<u8> = (0..150_000u32).map(|i| (i % 256) as u8).collect();

    client
        .create_bucket()
        .bucket(bucket)
        .send()
        .await
        .expect("create bucket");
    client
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(ByteStream::from(plaintext.clone()))
        .send()
        .await
        .expect("put object");

    let got = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .expect("get object — response headers, not the body yet");
    // Sleep well past S3A_TIMEOUT_REQUEST *before reading a single byte of
    // the body* — the failure mode this guards against is a timeout that
    // (wrongly) covers the whole request/response exchange, which would
    // have severed the connection during this sleep.
    tokio::time::sleep(timeout_request * 3).await;
    let bytes = got
        .body
        .collect()
        .await
        .expect("a slow client read must not be killed by S3A_TIMEOUT_REQUEST")
        .into_bytes();
    assert_eq!(bytes.as_ref(), plaintext.as_slice());
}

async fn raw_get(endpoint: &str, path: &str) -> http::Response<hyper::body::Incoming> {
    let http_client: hyper_util::client::legacy::Client<_, http_body_util::Empty<bytes::Bytes>> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();
    let req = http::Request::builder()
        .method("GET")
        .uri(format!("{endpoint}{path}"))
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .unwrap_or_else(|e| panic!("build GET {path} request: {e}"));
    http_client
        .request(req)
        .await
        .unwrap_or_else(|e| panic!("{path} must reach the proxy: {e}"))
}

/// `/health` must flip from `200` to `503` once
/// `ProxyState::set_draining` has run (`docs/ARCHITECTURE.md` "Observability"'s "503 during
/// drain") — a load balancer or `docker`'s own healthcheck stops routing
/// here while `serve`'s real shutdown sequence finishes in-flight work.
/// The real SIGTERM-triggered sequence lives entirely in `main::serve`
/// (this harness's accept loop is a simplified stand-in — see
/// `spawn_proxy_with_state`'s doc comment — that never calls
/// `set_draining` on its own), so it is exercised end-to-end against the
/// real binary by `scripts/lifecycle-check.sh`; this test covers `/health`'s own
/// reaction to the flag, which is library code and belongs here.
#[tokio::test]
async fn health_endpoint_flips_to_503_once_draining() {
    // No backend needed — `/health` never touches it.
    let (_client, endpoint, state) = spawn_proxy_with_state("http://127.0.0.1:1", |_| {}).await;

    assert_eq!(raw_get(&endpoint, "/health").await.status().as_u16(), 200);
    state.set_draining();
    assert_eq!(raw_get(&endpoint, "/health").await.status().as_u16(), 503);
}

/// `/ready` (`docs/ARCHITECTURE.md` "Observability", previously unbuilt — `GET /ready`
/// fell through to SigV4 verification and returned a bare `403`) must
/// report the *backend's* reachability, not just that this process is
/// alive: `200` against a live MinIO, `503` against a backend nothing
/// listens on.
#[tokio::test]
async fn ready_endpoint_reflects_backend_reachability() {
    let (_client, endpoint, _minio_endpoint, _minio) = setup().await;
    assert_eq!(
        raw_get(&endpoint, "/ready").await.status().as_u16(),
        200,
        "a live backend must answer /ready with 200"
    );

    // 127.0.0.1:1 is loopback with nothing listening — connection refused,
    // not a hang, so this resolves fast without needing a timeout.
    let (_client2, endpoint2) = spawn_proxy("http://127.0.0.1:1", |_| {}).await;
    assert_eq!(
        raw_get(&endpoint2, "/ready").await.status().as_u16(),
        503,
        "an unreachable backend must fail /ready, not report 200"
    );
}
