//! Path-style routing: `/bucket/key…` -> `{bucket, key}`. Path-style only —
//! all target clients (Nextcloud, Stalwart, rclone, restic, s3cmd, aws-cli)
//! support it, and virtual-hosted-style detection would need a configured
//! proxy domain this crate does not have (`S3A_LISTEN` is an address, not a
//! domain). `docs/ARCHITECTURE.md` "Architecture: re-signing streaming reverse proxy" defers the Host rewrite for virtual-hosted
//! style to a later stage; this parses what path-style traffic sends.

/// A parsed request target. `bucket = None` means the root (`ListBuckets`);
/// `key = None` with `bucket = Some` means a bucket-level operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub bucket: Option<String>,
    pub key: Option<String>,
}

/// A multipart-upload sub-operation, discriminated by query keys and
/// method — `docs/ARCHITECTURE.md` "Multipart v1"/"S3 operation matrix (v1)".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MpuOp {
    /// `POST ?uploads` — mint a session DEK, stamp v1 metadata, return the
    /// backend's own `InitiateMultipartUploadResult` unchanged.
    Create,
    /// `PUT ?partNumber&uploadId` — encrypt this part under the session DEK
    /// with `part_number` in the AAD.
    UploadPart,
    /// `PUT ?partNumber&uploadId` with `x-amz-copy-source` — copying a
    /// range of an existing object into a part server-side. Not supported
    /// in v1: ciphertext cannot be re-chunked server-side (`docs/ARCHITECTURE.md`
    /// "S3 operation matrix (v1)").
    UploadPartCopy,
    /// `POST ?uploadId` (no `partNumber`) — validate the part list, append
    /// the footer, complete.
    Complete,
    /// `DELETE ?uploadId` — drop the session.
    Abort,
    /// `GET ?uploadId` (no `partNumber`) — passthrough; part sizes are
    /// ciphertext sizes, same posture as List (`docs/ARCHITECTURE.md` "List sizes are ciphertext sizes").
    ListParts,
    /// `GET ?partNumber` (no `uploadId`) — fetch one part of an already
    /// completed multipart object. Not supported in v1.
    GetPart,
}

/// The operation an interceptor exists for, or `Passthrough` for everything
/// else (list, delete, ACLs, bucket sub-resources, …) — `docs/ARCHITECTURE.md` "Architecture: re-signing streaming reverse proxy".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    PutObject,
    GetObject,
    HeadObject,
    /// `PUT` with `x-amz-copy-source` set — a server-side copy, not a body
    /// upload. Classified separately from `PutObject` so it never runs
    /// through `intercept::put` (which would encrypt the empty request
    /// body and stamp v1 metadata onto what the backend treats as a copy —
    /// found while building this routing layer).
    CopyObject,
    Mpu(MpuOp),
    /// `POST` with `?select` in the query — `SelectObjectContent`. Not
    /// supported in v1: the backend would run the SQL expression over
    /// ciphertext, not the plaintext, and return wrong or empty results
    /// instead of an honest error (`docs/ARCHITECTURE.md` "S3 operation
    /// matrix (v1)").
    SelectObjectContent,
    Passthrough,
}

/// Classifies `(method, route, raw_query)` into an [`Op`]. `raw_query` is
/// the still-percent-encoded query string, matching `Route::parse`'s own
/// choice not to decode. `has_copy_source` is whether the request carries
/// `x-amz-copy-source` — that header, not the query string, is what turns a
/// `PUT` into a copy.
pub fn classify(method: &str, route: &Route, raw_query: &str, has_copy_source: bool) -> Op {
    let (Some(_bucket), Some(_key)) = (&route.bucket, &route.key) else {
        return Op::Passthrough;
    };
    if let Some(op) = classify_mpu(method, raw_query, has_copy_source) {
        return Op::Mpu(op);
    }
    if method == "POST" && query_has(raw_query, "select") {
        return Op::SelectObjectContent;
    }
    if has_sub_resource_query(raw_query) {
        // A sub-resource on an object key (e.g. `?acl`, `?tagging`) is not
        // a plain object body operation — let it pass through untouched.
        return Op::Passthrough;
    }
    match method {
        "PUT" if has_copy_source => Op::CopyObject,
        "PUT" => Op::PutObject,
        "GET" => Op::GetObject,
        "HEAD" => Op::HeadObject,
        _ => Op::Passthrough,
    }
}

fn query_pairs(raw_query: &str) -> impl Iterator<Item = &str> {
    raw_query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| pair.split('=').next().unwrap_or(pair))
}

fn query_has(raw_query: &str, key: &str) -> bool {
    query_pairs(raw_query).any(|k| k.eq_ignore_ascii_case(key))
}

/// The multipart-specific classifier `classify` delegates to. Returns
/// `None` for a request with none of `uploads`/`uploadId`/`partNumber` in
/// its query, so `classify` falls through to its plain PUT/GET/HEAD match.
fn classify_mpu(method: &str, raw_query: &str, has_copy_source: bool) -> Option<MpuOp> {
    let has_uploads = query_has(raw_query, "uploads");
    let has_upload_id = query_has(raw_query, "uploadId");
    let has_part_number = query_has(raw_query, "partNumber");
    if !has_uploads && !has_upload_id && !has_part_number {
        return None;
    }
    if has_upload_id && has_part_number {
        return Some(if has_copy_source {
            MpuOp::UploadPartCopy
        } else {
            MpuOp::UploadPart
        });
    }
    if has_uploads && method == "POST" {
        return Some(MpuOp::Create);
    }
    if has_upload_id {
        return match method {
            "POST" => Some(MpuOp::Complete),
            "DELETE" => Some(MpuOp::Abort),
            "GET" => Some(MpuOp::ListParts),
            _ => None,
        };
    }
    if has_part_number && method == "GET" {
        return Some(MpuOp::GetPart);
    }
    None
}

/// Any other recognized query key turns a PUT/GET/HEAD into an object
/// sub-resource operation this proxy does not intercept (e.g. `?acl`,
/// `?tagging`, `?retention`, `?legal-hold`). Conservative on purpose: an
/// *unrecognized* query key (or none) still classifies as a plain object
/// operation, since S3 clients attach no query at all for a plain PUT/GET.
fn has_sub_resource_query(raw_query: &str) -> bool {
    const OBJECT_SUB_RESOURCES: &[&str] = &[
        "acl",
        "tagging",
        "retention",
        "legal-hold",
        "torrent",
        "attributes",
    ];
    query_pairs(raw_query).any(|key| {
        OBJECT_SUB_RESOURCES
            .iter()
            .any(|s| key.eq_ignore_ascii_case(s))
    })
}

/// Splits a raw (still percent-encoded) request path into bucket and key.
/// Does **not** decode — the SigV4 canonicalizer needs the untouched wire
/// bytes (see `sigv4::canonical`'s doc comment on the decode/re-encode
/// hazard), and the key is only ever used for building the
/// *outbound* path, which must stay byte-identical to what the client sent.
pub fn parse(raw_path: &str) -> Route {
    let trimmed = raw_path.trim_start_matches('/');
    if trimmed.is_empty() {
        return Route {
            bucket: None,
            key: None,
        };
    }
    match trimmed.split_once('/') {
        Some((bucket, key)) if !key.is_empty() => Route {
            bucket: Some(bucket.to_string()),
            key: Some(key.to_string()),
        },
        Some((bucket, _)) => Route {
            bucket: Some(bucket.to_string()),
            key: None,
        },
        None => Route {
            bucket: Some(trimmed.to_string()),
            key: None,
        },
    }
}

/// Percent-decodes an object key for use as the v1 path-binding AAD: the
/// binding must match the actual object key, its decoded form, not the
/// wire-encoded request path. Unlike `url.QueryUnescape`-style form
/// decoding, path decoding never turns `+` into a space — this function
/// doesn't either (`percent_encoding` only ever touches `%XX` sequences).
/// Returns raw bytes, not a `String`: a decoded key is not guaranteed to be
/// valid UTF-8, and re-lossifying it would itself corrupt the AAD input
/// for a key that needed exactly those bytes.
pub fn decode_key(raw_key: &str) -> Vec<u8> {
    percent_encoding::percent_decode_str(raw_key).collect()
}

/// RFC 3986 unreserved set, matching `sigv4::canonical`'s own choice —
/// used here to build a *wire* request path from an unencoded key, not to
/// canonicalize one for signing.
const PATH_UNRESERVED: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// The inverse of [`decode_key`]: percent-encodes a plain-text key for use
/// as a request path, segment by segment so literal `/` (S3 "folder"
/// separators) stay unencoded. Used by `tools::rewrap` to turn a
/// `ListObjectsV2` key (plain XML text — see `tools::list`'s doc comment
/// on why it doesn't request `encoding-type=url`) into a request path.
pub fn encode_key_for_path(key: &str) -> String {
    key.split('/')
        .map(|seg| percent_encoding::utf8_percent_encode(seg, PATH_UNRESERVED).to_string())
        .collect::<Vec<_>>()
        .join("/")
}

/// Parses `x-amz-copy-source`: `[/]bucket/key`, both possibly with a
/// `?versionId=...` suffix (dropped — this proxy has no version-aware
/// routing to do with it, and the backend gets the header verbatim
/// regardless of what this parses). Percent-decoded pieces are not
/// re-encoded; this exists only to `HEAD` the source through the same
/// `forward` path other routes use, which itself re-encodes nothing either.
pub fn parse_copy_source(header_value: &str) -> Option<Route> {
    let trimmed = header_value.trim_start_matches('/');
    let without_version = trimmed.split('?').next().unwrap_or(trimmed);
    let (bucket, key) = without_version.split_once('/')?;
    if bucket.is_empty() || key.is_empty() {
        return None;
    }
    Some(Route {
        bucket: Some(bucket.to_string()),
        key: Some(key.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_has_no_bucket() {
        assert_eq!(
            parse("/"),
            Route {
                bucket: None,
                key: None
            }
        );
        assert_eq!(
            parse(""),
            Route {
                bucket: None,
                key: None
            }
        );
    }

    #[test]
    fn path_without_a_key_parses_as_bucket_only() {
        assert_eq!(
            parse("/mybucket"),
            Route {
                bucket: Some("mybucket".to_string()),
                key: None
            }
        );
        assert_eq!(
            parse("/mybucket/"),
            Route {
                bucket: Some("mybucket".to_string()),
                key: None
            }
        );
    }

    #[test]
    fn key_keeps_its_internal_slashes() {
        assert_eq!(
            parse("/mybucket/path/to/object.txt"),
            Route {
                bucket: Some("mybucket".to_string()),
                key: Some("path/to/object.txt".to_string()),
            }
        );
    }

    #[test]
    fn plain_put_get_head_classify_as_object_ops() {
        let route = parse("/b/key");
        assert_eq!(classify("PUT", &route, "", false), Op::PutObject);
        assert_eq!(classify("GET", &route, "", false), Op::GetObject);
        assert_eq!(classify("HEAD", &route, "", false), Op::HeadObject);
    }

    #[test]
    fn bucket_only_or_no_key_is_passthrough() {
        assert_eq!(classify("GET", &parse("/b"), "", false), Op::Passthrough);
        assert_eq!(classify("GET", &parse("/"), "", false), Op::Passthrough);
    }

    #[test]
    fn multipart_queries_classify_by_op() {
        let route = parse("/b/key");
        assert_eq!(
            classify("POST", &route, "uploads", false),
            Op::Mpu(MpuOp::Create)
        );
        assert_eq!(
            classify("PUT", &route, "partNumber=1&uploadId=abc", false),
            Op::Mpu(MpuOp::UploadPart)
        );
        assert_eq!(
            classify("POST", &route, "uploadId=abc", false),
            Op::Mpu(MpuOp::Complete)
        );
        assert_eq!(
            classify("DELETE", &route, "uploadId=abc", false),
            Op::Mpu(MpuOp::Abort)
        );
        assert_eq!(
            classify("GET", &route, "uploadId=abc", false),
            Op::Mpu(MpuOp::ListParts)
        );
        assert_eq!(
            classify("GET", &route, "partNumber=1", false),
            Op::Mpu(MpuOp::GetPart)
        );
    }

    #[test]
    fn select_object_content_classifies_as_select() {
        let route = parse("/b/key");
        assert_eq!(
            classify("POST", &route, "select&select-type=2", false),
            Op::SelectObjectContent
        );
        assert_eq!(
            classify("POST", &route, "select", false),
            Op::SelectObjectContent
        );
        // Only POST is Select — a plain GET with the same query is not.
        assert_eq!(
            classify("GET", &route, "select&select-type=2", false),
            Op::GetObject
        );
        // A POST on an object key without `select` is not classified as Select.
        assert_eq!(classify("POST", &route, "", false), Op::Passthrough);
    }

    #[test]
    fn object_sub_resource_queries_pass_through() {
        let route = parse("/b/key");
        assert_eq!(classify("GET", &route, "acl", false), Op::Passthrough);
        assert_eq!(classify("PUT", &route, "tagging", false), Op::Passthrough);
    }

    #[test]
    fn copy_source_header_classifies_a_put_as_copy() {
        let route = parse("/b/key");
        assert_eq!(classify("PUT", &route, "", true), Op::CopyObject);
        // Multipart still wins — an UploadPartCopy carries copy-source too.
        assert_eq!(
            classify("PUT", &route, "partNumber=1&uploadId=abc", true),
            Op::Mpu(MpuOp::UploadPartCopy)
        );
    }

    #[test]
    fn encode_key_for_path_percent_encodes_segments_but_not_slashes() {
        assert_eq!(encode_key_for_path("a dir/b.txt"), "a%20dir/b.txt");
        assert_eq!(encode_key_for_path("plus+sign.txt"), "plus%2Bsign.txt");
        assert_eq!(
            decode_key(&encode_key_for_path("a dir/b c.txt")),
            b"a dir/b c.txt".to_vec(),
            "encode then decode must round-trip"
        );
    }

    #[test]
    fn decode_key_undoes_percent_encoding_without_touching_plus() {
        assert_eq!(decode_key("a%20b"), b"a b".to_vec());
        assert_eq!(decode_key("a+b"), b"a+b".to_vec());
        assert_eq!(decode_key("a%2520b"), b"a%20b".to_vec());
    }

    #[test]
    fn parse_copy_source_reads_bucket_and_key() {
        assert_eq!(
            parse_copy_source("/src-bucket/src/key.txt"),
            Some(Route {
                bucket: Some("src-bucket".to_string()),
                key: Some("src/key.txt".to_string()),
            })
        );
        assert_eq!(
            parse_copy_source("src-bucket/key.txt?versionId=abc"),
            Some(Route {
                bucket: Some("src-bucket".to_string()),
                key: Some("key.txt".to_string()),
            })
        );
        assert_eq!(parse_copy_source("no-slash"), None);
    }

    #[test]
    fn key_stays_percent_encoded() {
        assert_eq!(
            parse("/b/a%20b"),
            Route {
                bucket: Some("b".to_string()),
                key: Some("a%20b".to_string())
            }
        );
    }
}
