//! `s3armor check`: preflight backend conformance probe. `docs/ARCHITECTURE.md`
//! "Backend conformance check (`s3armor check`)". Every probe talks
//! direct-to-backend through the same `proxy::forward` signing path
//! `rewrap` uses — this checks whether the *backend* will work correctly
//! with the proxy, not the
//! proxy's own crypto (that's covered by the integration suite). All
//! objects it writes live under one UUID-ish prefix and are always deleted,
//! win or lose.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use bytes::Bytes;
use http_body_util::BodyExt;

use crate::config::Backend;
use crate::intercept::mpu::{build_complete_xml, parse_single_tag};
use crate::proxy::body;
use crate::proxy::headers::to_pairs;
use crate::proxy::route::encode_key_for_path;
use crate::proxy::{forward, set_header, ProxyState};

/// One probe's outcome. `Fail` on the hard requirements (docs/ARCHITECTURE.md "Backend conformance check (`s3armor check`)"'s checked
/// list); `Warn` for something degraded but not disqualifying (e.g. no
/// clock to compare, TLS not in use).
enum Status {
    Ok,
    Warn(String),
    Fail(String),
}

struct Probe {
    name: &'static str,
    status: Status,
}

pub struct CheckReport {
    probes: Vec<Probe>,
}

impl CheckReport {
    pub fn print(&self) {
        for p in &self.probes {
            match &p.status {
                Status::Ok => println!("  \u{2713} {}", p.name),
                Status::Warn(msg) => println!("  ! {} — {msg}", p.name),
                Status::Fail(msg) => println!("  \u{2717} {} — {msg}", p.name),
            }
        }
        println!("verdict: {}", self.verdict());
    }

    fn verdict(&self) -> &'static str {
        if self
            .probes
            .iter()
            .any(|p| matches!(p.status, Status::Fail(_)))
        {
            "incompatible"
        } else if self
            .probes
            .iter()
            .any(|p| matches!(p.status, Status::Warn(_)))
        {
            "degraded"
        } else {
            "compatible"
        }
    }

    /// Non-zero exit on `incompatible` — the only verdict that means "do
    /// not point production traffic at this backend."
    pub fn ok(&self) -> bool {
        self.verdict() != "incompatible"
    }
}

fn header_owned(pairs: &[(String, String)], name: &str) -> Option<String> {
    pairs
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

/// Runs every probe against `bucket` (must already exist) and returns the
/// full report. Never leaves objects behind: each probe cleans up its own
/// key before returning, success or failure.
pub async fn check(state: &ProxyState, backend: &Backend, bucket: &str) -> CheckReport {
    let prefix = format!("s3a-check-{:x}", probe_nonce());
    let probes = vec![
        tls_probe(state, backend),
        reachable_and_auth_probe(state, backend, bucket).await,
        round_trip_probe(state, backend, bucket, &prefix).await,
        metadata_survives_probe(state, backend, bucket, &prefix).await,
        metadata_headroom_probe(state, backend, bucket, &prefix).await,
        ranged_get_probe(state, backend, bucket, &prefix).await,
        copy_preserves_metadata_probe(state, backend, bucket, &prefix).await,
        checksum_header_probe(state, backend, bucket, &prefix).await,
        multipart_small_final_part_probe(state, backend, bucket, &prefix).await,
    ];

    CheckReport { probes }
}

/// A per-run key suffix — not `rand`, this crate has no general-purpose RNG
/// dependency at the CLI layer; the system clock is unique enough for a
/// scratch-object prefix that lives for the duration of one `check` run.
fn probe_nonce() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

fn tls_probe(_state: &ProxyState, backend: &Backend) -> Probe {
    let name = "endpoint reachable, TLS in use";
    if backend.endpoint.starts_with("https://") {
        Probe {
            name,
            status: Status::Ok,
        }
    } else {
        Probe {
            name,
            status: Status::Warn(format!(
                "backend {}'s endpoint {} is not https:// — ciphertext streams to the backend \
                 over TLS keep the outer channel confidential too; plaintext HTTP defeats that \
                 (docs/ARCHITECTURE.md 'UNSIGNED-PAYLOAD to the backend over TLS')",
                backend.name, backend.endpoint
            )),
        }
    }
}

async fn reachable_and_auth_probe(state: &ProxyState, backend: &Backend, bucket: &str) -> Probe {
    let name = "auth valid, backend reachable, clock skew";
    let path = format!("/{bucket}");
    let resp = match forward(state, backend, "HEAD", &path, "", Vec::new(), body::empty()).await {
        Ok(r) => r,
        Err(e) => {
            return Probe {
                name,
                status: Status::Fail(format!("HeadBucket failed: {e}")),
            }
        }
    };
    if !resp.status().is_success() {
        return Probe {
            name,
            status: Status::Fail(format!(
                "HeadBucket returned {} — check credentials and that the bucket exists",
                resp.status()
            )),
        };
    }
    let pairs = to_pairs(resp.headers());
    let Some(date) = header_owned(&pairs, "date") else {
        return Probe {
            name,
            status: Status::Warn("backend sent no Date header — cannot check clock skew".into()),
        };
    };
    let Ok(backend_time) = httpdate::parse_http_date(&date) else {
        return Probe {
            name,
            status: Status::Warn(format!("backend Date header did not parse: {date}")),
        };
    };
    let skew = backend_time
        .duration_since(SystemTime::now())
        .or_else(|_| SystemTime::now().duration_since(backend_time))
        .unwrap_or_default();
    if skew > Duration::from_mins(15) {
        Probe {
            name,
            status: Status::Fail(format!(
                "backend clock is {skew:?} away from this host's — SigV4 rejects requests \
                 outside \u{00b1}15 min; fix NTP on one side"
            )),
        }
    } else {
        Probe {
            name,
            status: Status::Ok,
        }
    }
}

async fn round_trip_probe(
    state: &ProxyState,
    backend: &Backend,
    bucket: &str,
    prefix: &str,
) -> Probe {
    let name = "put/get/delete round-trip (1 KiB)";
    let key = format!("{prefix}/roundtrip");
    let path = format!("/{bucket}/{}", encode_key_for_path(&key));
    let body_bytes = Bytes::from(vec![0x5Au8; 1024]);

    let mut headers = Vec::new();
    set_header(&mut headers, "content-length", "1024");
    let put = match forward(
        state,
        backend,
        "PUT",
        &path,
        "",
        headers,
        body::full(body_bytes.clone()),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            return Probe {
                name,
                status: Status::Fail(format!("PUT failed: {e}")),
            }
        }
    };
    if !put.status().is_success() {
        return Probe {
            name,
            status: Status::Fail(format!("PUT returned {}", put.status())),
        };
    }

    let status = match forward(state, backend, "GET", &path, "", Vec::new(), body::empty()).await {
        Ok(resp) if resp.status().is_success() => {
            let got = resp
                .into_body()
                .collect()
                .await
                .map(http_body_util::Collected::to_bytes)
                .unwrap_or_default();
            if got == body_bytes {
                Status::Ok
            } else {
                Status::Fail("GET returned different bytes than were PUT".to_string())
            }
        }
        Ok(resp) => Status::Fail(format!("GET returned {}", resp.status())),
        Err(e) => Status::Fail(format!("GET failed: {e}")),
    };
    delete(state, backend, bucket, &key).await;
    Probe { name, status }
}

async fn metadata_survives_probe(
    state: &ProxyState,
    backend: &Backend,
    bucket: &str,
    prefix: &str,
) -> Probe {
    let name = "user metadata survives PUT -> HEAD";
    let key = format!("{prefix}/metadata");
    let path = format!("/{bucket}/{}", encode_key_for_path(&key));
    let mut headers = Vec::new();
    set_header(&mut headers, "content-length", "4");
    set_header(&mut headers, "x-amz-meta-s3a-v", "1");
    set_header(&mut headers, "x-amz-meta-s3a-kid", "0123456789abcdef");
    let put = forward(
        state,
        backend,
        "PUT",
        &path,
        "",
        headers,
        body::full(Bytes::from_static(b"test")),
    )
    .await;
    let status = match put {
        Ok(resp) if resp.status().is_success() => {
            match forward(state, backend, "HEAD", &path, "", Vec::new(), body::empty()).await {
                Ok(head) => {
                    let pairs = to_pairs(head.headers());
                    let ok = header_owned(&pairs, "x-amz-meta-s3a-v").as_deref() == Some("1")
                        && header_owned(&pairs, "x-amz-meta-s3a-kid").as_deref()
                            == Some("0123456789abcdef");
                    if ok {
                        Status::Ok
                    } else {
                        Status::Fail(
                            "s3a-* user metadata did not survive a PUT -> HEAD round-trip — the \
                             format cannot work against this backend"
                                .to_string(),
                        )
                    }
                }
                Err(e) => Status::Fail(format!("HEAD failed: {e}")),
            }
        }
        Ok(resp) => Status::Fail(format!("PUT returned {}", resp.status())),
        Err(e) => Status::Fail(format!("PUT failed: {e}")),
    };
    delete(state, backend, bucket, &key).await;
    Probe { name, status }
}

async fn metadata_headroom_probe(
    state: &ProxyState,
    backend: &Backend,
    bucket: &str,
    prefix: &str,
) -> Probe {
    let name = "metadata size headroom (real v1 worst case fits)";
    let key = format!("{prefix}/headroom");
    let path = format!("/{bucket}/{}", encode_key_for_path(&key));
    // S3's own total-user-metadata cap is 2 KB (AWS enforces it; MinIO
    // matches it) — deliberately exceeding that is expected to fail on any
    // compliant backend, not a defect to probe for. What actually matters
    // is whether v1's real worst case fits: a 4096-bit RSA wrap is ~684
    // base64 chars (`s3a-dek`), plus the other ~10 small `s3a-*` fields —
    // well under 900 bytes total. 1200 bytes here is a comfortable margin
    // above that, still safely inside the 2 KB hard ceiling.
    let padding = "a".repeat(1200);
    let mut headers = Vec::new();
    set_header(&mut headers, "content-length", "0");
    set_header(&mut headers, "x-amz-meta-s3a-check-padding", &padding);
    let status = match forward(state, backend, "PUT", &path, "", headers, body::empty()).await {
        Ok(resp) if resp.status().is_success() => Status::Ok,
        Ok(resp) => Status::Fail(format!(
            "PUT with 1200 bytes of metadata (v1's real worst case, RSA wrap included, is under \
             900) returned {} — headroom is below what v1 objects need",
            resp.status()
        )),
        Err(e) => Status::Fail(format!("PUT failed: {e}")),
    };
    delete(state, backend, bucket, &key).await;
    Probe { name, status }
}

async fn ranged_get_probe(
    state: &ProxyState,
    backend: &Backend,
    bucket: &str,
    prefix: &str,
) -> Probe {
    let name = "ranged GET honored (bytes=5-9 -> 206)";
    let key = format!("{prefix}/ranged");
    let path = format!("/{bucket}/{}", encode_key_for_path(&key));
    let mut headers = Vec::new();
    set_header(&mut headers, "content-length", "20");
    // Check the setup PUT: a failed setup would otherwise misdiagnose as
    // "ranged GET returned 404", pointing the operator at the wrong feature.
    match forward(
        state,
        backend,
        "PUT",
        &path,
        "",
        headers,
        body::full(Bytes::from(vec![0x11u8; 20])),
    )
    .await
    {
        Ok(r) if r.status().is_success() => {}
        Ok(r) => {
            return Probe {
                name,
                status: Status::Fail(format!("setup PUT returned {}", r.status())),
            }
        }
        Err(e) => {
            return Probe {
                name,
                status: Status::Fail(format!("setup PUT failed: {e}")),
            }
        }
    }

    let mut get_headers = Vec::new();
    set_header(&mut get_headers, "range", "bytes=5-9");
    let status = match forward(state, backend, "GET", &path, "", get_headers, body::empty()).await {
        Ok(resp) if resp.status().as_u16() == 206 => Status::Ok,
        Ok(resp) => Status::Warn(format!(
            "ranged GET returned {} instead of 206 — the proxy's ranged reads depend on this",
            resp.status()
        )),
        Err(e) => Status::Fail(format!("ranged GET failed: {e}")),
    };
    delete(state, backend, bucket, &key).await;
    Probe { name, status }
}

async fn copy_preserves_metadata_probe(
    state: &ProxyState,
    backend: &Backend,
    bucket: &str,
    prefix: &str,
) -> Probe {
    let name = "CopyObject preserves user metadata";
    let src_key = format!("{prefix}/copy-src");
    let dst_key = format!("{prefix}/copy-dst");
    let src_path = format!("/{bucket}/{}", encode_key_for_path(&src_key));
    let dst_path = format!("/{bucket}/{}", encode_key_for_path(&dst_key));

    let mut put_headers = Vec::new();
    set_header(&mut put_headers, "content-length", "4");
    set_header(&mut put_headers, "x-amz-meta-s3a-v", "1");
    // A failed setup PUT would misdiagnose as "CopyObject returned 404".
    match forward(
        state,
        backend,
        "PUT",
        &src_path,
        "",
        put_headers,
        body::full(Bytes::from_static(b"copy")),
    )
    .await
    {
        Ok(r) if r.status().is_success() => {}
        Ok(r) => {
            return Probe {
                name,
                status: Status::Fail(format!("setup PUT returned {}", r.status())),
            }
        }
        Err(e) => {
            return Probe {
                name,
                status: Status::Fail(format!("setup PUT failed: {e}")),
            }
        }
    }

    let mut copy_headers = Vec::new();
    set_header(
        &mut copy_headers,
        "x-amz-copy-source",
        &format!("/{bucket}/{}", encode_key_for_path(&src_key)),
    );
    let status = match forward(
        state,
        backend,
        "PUT",
        &dst_path,
        "",
        copy_headers,
        body::empty(),
    )
    .await
    {
        Ok(resp) if resp.status().is_success() => {
            match forward(
                state,
                backend,
                "HEAD",
                &dst_path,
                "",
                Vec::new(),
                body::empty(),
            )
            .await
            {
                Ok(head) => {
                    let pairs = to_pairs(head.headers());
                    if header_owned(&pairs, "x-amz-meta-s3a-v").as_deref() == Some("1") {
                        Status::Ok
                    } else {
                        Status::Fail("CopyObject dropped user metadata".to_string())
                    }
                }
                Err(e) => Status::Fail(format!("HEAD of copy failed: {e}")),
            }
        }
        Ok(resp) => Status::Fail(format!("CopyObject returned {}", resp.status())),
        Err(e) => Status::Fail(format!("CopyObject failed: {e}")),
    };
    delete(state, backend, bucket, &src_key).await;
    delete(state, backend, bucket, &dst_key).await;
    Probe { name, status }
}

/// CRC32 (IEEE 802.3 / zlib polynomial) — what `x-amz-checksum-crc32`
/// carries. `check` talks direct-to-backend (like `rewrap`), not
/// through the proxy's own checksum-stripping (`proxy::headers`), so the
/// backend validates this value against the body for real — a fabricated
/// value gets correctly rejected, not proof of anything. No new dependency
/// for one CRC32 call in a CLI probe.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

async fn checksum_header_probe(
    state: &ProxyState,
    backend: &Backend,
    bucket: &str,
    prefix: &str,
) -> Probe {
    let name = "modern checksum header accepted";
    let key = format!("{prefix}/checksum");
    let path = format!("/{bucket}/{}", encode_key_for_path(&key));
    let body_bytes = Bytes::from_static(b"checksum me");
    let checksum = B64.encode(crc32(&body_bytes).to_be_bytes());
    let mut headers = Vec::new();
    set_header(
        &mut headers,
        "content-length",
        &body_bytes.len().to_string(),
    );
    set_header(&mut headers, "x-amz-checksum-crc32", &checksum);
    set_header(&mut headers, "x-amz-sdk-checksum-algorithm", "CRC32");
    let status = match forward(
        state,
        backend,
        "PUT",
        &path,
        "",
        headers,
        body::full(body_bytes),
    )
    .await
    {
        Ok(resp) if resp.status().is_success() => Status::Ok,
        Ok(resp) => Status::Warn(format!(
            "PUT with a checksum header returned {} — a modern SDK's default checksum-on-write \
             may fail against this backend",
            resp.status()
        )),
        Err(e) => Status::Fail(format!("PUT failed: {e}")),
    };
    delete(state, backend, bucket, &key).await;
    Probe { name, status }
}

/// The footer's tail-merge requirement (docs/ARCHITECTURE.md "Multipart v1"): every part
/// but the last must be >= 5 MiB, except S3 must still accept the actual
/// last part being small. Two parts, first >= 5 MiB, second 1 KiB.
async fn multipart_small_final_part_probe(
    state: &ProxyState,
    backend: &Backend,
    bucket: &str,
    prefix: &str,
) -> Probe {
    const FIVE_MIB: usize = 5 * 1024 * 1024;
    let name = "multipart accepts a small final part";
    let key = format!("{prefix}/multipart");
    let path = format!("/{bucket}/{}", encode_key_for_path(&key));

    let create = match forward(
        state,
        backend,
        "POST",
        &path,
        "uploads",
        Vec::new(),
        body::empty(),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            return Probe {
                name,
                status: Status::Fail(format!("CreateMultipartUpload failed: {e}")),
            }
        }
    };
    if !create.status().is_success() {
        return Probe {
            name,
            status: Status::Fail(format!(
                "CreateMultipartUpload returned {}",
                create.status()
            )),
        };
    }
    let xml = match create.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(e) => {
            return Probe {
                name,
                status: Status::Fail(format!("reading CreateMultipartUpload body: {e}")),
            }
        }
    };
    let Some(upload_id) = parse_single_tag(&xml, b"UploadId") else {
        return Probe {
            name,
            status: Status::Fail("backend did not return an UploadId".to_string()),
        };
    };
    let encoded_id = encode_key_for_path(&upload_id);

    let mut etags = Vec::new();
    for (number, size) in [(1u32, FIVE_MIB), (2, 1024)] {
        let mut headers = Vec::new();
        set_header(&mut headers, "content-length", &size.to_string());
        let query = format!("partNumber={number}&uploadId={encoded_id}");
        let resp = forward(
            state,
            backend,
            "PUT",
            &path,
            &query,
            headers,
            body::full(Bytes::from(vec![0x22u8; size])),
        )
        .await;
        match resp {
            Ok(r) if r.status().is_success() => {
                let etag = header_owned(&to_pairs(r.headers()), "etag").unwrap_or_default();
                etags.push((number, etag));
            }
            Ok(r) => {
                let abort_query = format!("uploadId={encoded_id}");
                let _ = forward(
                    state,
                    backend,
                    "DELETE",
                    &path,
                    &abort_query,
                    Vec::new(),
                    body::empty(),
                )
                .await;
                return Probe {
                    name,
                    status: Status::Fail(format!("UploadPart {number} returned {}", r.status())),
                };
            }
            Err(e) => {
                abort_upload(state, backend, &path, &encoded_id).await;
                return Probe {
                    name,
                    status: Status::Fail(format!("UploadPart {number} failed: {e}")),
                };
            }
        }
    }

    let status = complete_small_final_part(state, backend, &path, &encoded_id, &etags).await;
    delete(state, backend, bucket, &key).await;
    Probe { name, status }
}

/// Sends `CompleteMultipartUpload` for the probe and turns the outcome into a
/// `Status`, aborting the upload on any failure so no parts are orphaned. S3
/// can return 200 with an `<Error>` body for a late Complete failure, so the
/// success body is inspected too.
async fn complete_small_final_part(
    state: &ProxyState,
    backend: &Backend,
    path: &str,
    encoded_id: &str,
    etags: &[(u32, String)],
) -> Status {
    let complete_xml = build_complete_xml(etags);
    let mut complete_headers = Vec::new();
    set_header(
        &mut complete_headers,
        "content-length",
        &complete_xml.len().to_string(),
    );
    let complete_query = format!("uploadId={encoded_id}");
    let resp = forward(
        state,
        backend,
        "POST",
        path,
        &complete_query,
        complete_headers,
        body::full(Bytes::from(complete_xml)),
    )
    .await;
    let ok = match resp {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            abort_upload(state, backend, path, encoded_id).await;
            return Status::Fail(format!(
                "CompleteMultipartUpload with a small final part returned {} — this backend \
                 rejects the footer tail-merge this format relies on (docs/ARCHITECTURE.md 'Multipart v1')",
                r.status()
            ));
        }
        Err(e) => {
            abort_upload(state, backend, path, encoded_id).await;
            return Status::Fail(format!("CompleteMultipartUpload failed: {e}"));
        }
    };
    match ok.into_body().collect().await {
        Ok(b) => {
            if b.to_bytes().windows(6).any(|w| w == b"<Error") {
                abort_upload(state, backend, path, encoded_id).await;
                Status::Fail(
                    "CompleteMultipartUpload returned 200 with an <Error> body — this backend \
                     rejects the small-final-part footer tail-merge this format relies on \
                     (docs/ARCHITECTURE.md 'Multipart v1')"
                        .to_string(),
                )
            } else {
                Status::Ok
            }
        }
        Err(e) => Status::Fail(format!("reading CompleteMultipartUpload body: {e}")),
    }
}

/// Aborts an in-progress multipart upload so a failed probe leaves no
/// orphaned parts behind. `encoded_id` is the already-path-encoded uploadId.
async fn abort_upload(state: &ProxyState, backend: &Backend, path: &str, encoded_id: &str) {
    let _ = forward(
        state,
        backend,
        "DELETE",
        path,
        &format!("uploadId={encoded_id}"),
        Vec::new(),
        body::empty(),
    )
    .await;
}

async fn delete(state: &ProxyState, backend: &Backend, bucket: &str, key: &str) {
    let path = format!("/{bucket}/{}", encode_key_for_path(key));
    let _ = forward(
        state,
        backend,
        "DELETE",
        &path,
        "",
        Vec::new(),
        body::empty(),
    )
    .await;
}
