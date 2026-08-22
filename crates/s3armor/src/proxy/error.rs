//! The one error -> S3 XML mapper: a single typed path from an internal
//! failure to a well-formed, escaped S3 error response, so there is never
//! more than one XML shape or a raw interpolated string to get wrong.

use bytes::Bytes;
use http::{Response, StatusCode};

use crate::sigv4::verify::VerifyError;

use super::body::{self, ProxyBody};

/// An S3-shaped error: HTTP status, the `<Code>` S3 clients switch on, and
/// a human message. Every response carries the request's actual
/// correlation id in `<RequestId>` and in an `x-amz-request-id` header.
pub struct S3Error {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

impl std::fmt::Display for S3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({}): {}", self.code, self.status, self.message)
    }
}

impl S3Error {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    pub fn access_denied(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "AccessDenied", message)
    }

    pub fn signature_does_not_match() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "SignatureDoesNotMatch",
            "The request signature we calculated does not match the signature you provided",
        )
    }

    pub fn request_time_too_skewed() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "RequestTimeTooSkewed",
            "The difference between the request time and the current time is too large",
        )
    }

    pub fn expired_token() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "ExpiredToken",
            "The presigned URL has expired",
        )
    }

    pub fn invalid_access_key() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "InvalidAccessKeyId",
            "The access key ID you provided does not exist in our records",
        )
    }

    pub fn not_implemented(op: &str) -> Self {
        Self::new(
            StatusCode::NOT_IMPLEMENTED,
            "NotImplemented",
            format!("{op} is not supported by this proxy"),
        )
    }

    pub fn bad_gateway(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_GATEWAY, "BadGateway", message)
    }

    /// `S3A_TIMEOUT_CONNECT`/`S3A_TIMEOUT_REQUEST` elapsed waiting on the
    /// backend (`proxy::forward`) — bounds the connect-and-response-headers
    /// phase only, never a body already streaming (`docs/ARCHITECTURE.md` "Configuration model").
    pub fn gateway_timeout(message: impl Into<String>) -> Self {
        Self::new(StatusCode::GATEWAY_TIMEOUT, "GatewayTimeout", message)
    }

    /// This source IP has failed auth too many times recently
    /// (`S3A_AUTH_FAIL_LIMIT`, `crate::ratelimit`) — `429` with S3's own
    /// `SlowDown` code, so ordinary S3 clients apply their existing
    /// retry/backoff instead of treating it as a hard failure.
    pub fn slow_down() -> Self {
        Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            "SlowDown",
            "Too many failed authentication attempts from this address; slow down.",
        )
    }

    /// PUT with no usable length — S3 requires one, and format v1 needs the
    /// exact plaintext length to compute the ciphertext `content-length`
    /// before the body streams (`docs/ARCHITECTURE.md` "Data: chunked AEAD").
    pub fn missing_content_length() -> Self {
        Self::new(
            StatusCode::LENGTH_REQUIRED,
            "MissingContentLength",
            "You must provide the Content-Length HTTP header.",
        )
    }

    /// The object names a key id this node cannot resolve: unknown
    /// (rotated out and not configured), or an RSA write-only node without
    /// the private half (`docs/ARCHITECTURE.md` "Keys and wrap").
    pub fn key_not_available(kid: &str) -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "KeyNotAvailable",
            format!("no usable key for key id {kid}"),
        )
    }

    /// A `Range` request that names no valid slice of the object.
    pub fn invalid_range() -> Self {
        Self::new(
            StatusCode::RANGE_NOT_SATISFIABLE,
            "InvalidRange",
            "The requested range cannot be satisfied.",
        )
    }

    /// An `uploadId` this node has no session for: never created here,
    /// already completed/aborted and expired by TTL, or lost to a restart
    /// (`docs/ARCHITECTURE.md` "Multipart v1", "Multipart sessions are RAM, single instance"). `UploadPart`/`Complete`/`Abort` must
    /// fail this way rather than fall back to passthrough — a passthrough
    /// UploadPart would silently store plaintext.
    pub fn no_such_upload(upload_id: &str) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "NoSuchUpload",
            format!("The specified upload does not exist: {upload_id}"),
        )
    }

    /// The client's `If-Match`/`If-None-Match` conditional did not hold
    /// against this proxy's effective ETag (`docs/ARCHITECTURE.md` "ETag policy") — the
    /// same status a real backend would return, just evaluated against the
    /// plaintext ETag this proxy hands out rather than the ciphertext one.
    pub fn precondition_failed() -> Self {
        Self::new(
            StatusCode::PRECONDITION_FAILED,
            "PreconditionFailed",
            "At least one of the pre-conditions you specified did not hold",
        )
    }

    /// `CompleteMultipartUpload`'s part list disagrees with what this node
    /// recorded for the upload — wrong ETag, or a part number never
    /// uploaded (`docs/ARCHITECTURE.md` "Multipart v1").
    pub fn invalid_part(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "InvalidPart", message)
    }

    /// Renders the XML error body and a complete response, correlation id
    /// included in both the body and the `x-amz-request-id` header.
    #[expect(
        clippy::expect_used,
        reason = "a well-formed error response never fails to build"
    )]
    pub fn into_response(self, request_id: &str) -> Response<ProxyBody> {
        let mut escaped_message = String::with_capacity(self.message.len());
        for c in self.message.chars() {
            match c {
                '&' => escaped_message.push_str("&amp;"),
                '<' => escaped_message.push_str("&lt;"),
                '>' => escaped_message.push_str("&gt;"),
                '"' => escaped_message.push_str("&quot;"),
                '\'' => escaped_message.push_str("&apos;"),
                c => escaped_message.push(c),
            }
        }
        let body = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <Error><Code>{}</Code><Message>{escaped_message}</Message><RequestId>{request_id}</RequestId></Error>",
            self.code
        );
        Response::builder()
            .status(self.status)
            .header("Content-Type", "application/xml")
            .header("x-amz-request-id", request_id)
            .body(body::full(Bytes::from(body)))
            .expect("a well-formed error response never fails to build")
    }
}

/// A format v1 failure (wrap/unwrap, frame auth, metadata decode). Every
/// variant is either "this key/object isn't usable" or "the object failed
/// to authenticate" — both map to a definite, non-leaky status.
impl From<s3armor_format::Error> for S3Error {
    fn from(e: s3armor_format::Error) -> Self {
        match e {
            s3armor_format::Error::KeyNotAvailable => Self::key_not_available("?"),
            // A failed AEAD tag: the object actually failed integrity
            // verification, "this data is not trustworthy" — must never be
            // reported as a generic gateway problem the client might retry
            // past.
            s3armor_format::Error::UnwrapFailed
            | s3armor_format::Error::AuthFailed
            | s3armor_format::Error::Truncated { .. }
            | s3armor_format::Error::InvalidLength
            | s3armor_format::Error::InvalidFooter => {
                Self::new(StatusCode::FORBIDDEN, "AccessDenied", e.to_string())
            }
            s3armor_format::Error::UnknownVersion(_)
            | s3armor_format::Error::UnknownAlg(_)
            | s3armor_format::Error::MissingMetadata(_)
            | s3armor_format::Error::InvalidMetadata { .. } => {
                Self::new(StatusCode::BAD_GATEWAY, "BadGateway", e.to_string())
            }
        }
    }
}

impl From<VerifyError> for S3Error {
    fn from(e: VerifyError) -> Self {
        match e {
            VerifyError::NoAuth
            | VerifyError::MalformedAuthHeader
            | VerifyError::MalformedPresignedQuery
            | VerifyError::BadSignedHeaders(_)
            | VerifyError::BadScope
            | VerifyError::BadExpires
            | VerifyError::MissingHeader(_) => Self::access_denied(e.to_string()),
            VerifyError::UnknownAccessKey => Self::invalid_access_key(),
            VerifyError::ClockSkew | VerifyError::DateMismatch => Self::request_time_too_skewed(),
            VerifyError::BadSignature => Self::signature_does_not_match(),
            VerifyError::Expired => Self::expired_token(),
        }
    }
}

#[cfg(test)]
mod tests {
    use http_body_util::BodyExt;

    use super::*;

    #[test]
    fn error_response_carries_status_and_request_id() {
        let err = S3Error::access_denied("<script>&\"'</script>");
        let resp = err.into_response("req-1");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(resp.headers().get("x-amz-request-id").unwrap(), "req-1");
    }

    /// The name above only promises status/request-id — this checks the
    /// thing an attacker-controlled message actually threatens: that it
    /// reaches the client XML-escaped, not injected raw into the body.
    #[tokio::test]
    async fn message_body_is_xml_escaped() {
        let err = S3Error::access_denied("<script>&\"'</script>");
        let resp = err.into_response("req-1");
        let body = resp
            .into_body()
            .collect()
            .await
            .expect("a full body never fails to collect")
            .to_bytes();
        let body = String::from_utf8(body.to_vec()).expect("error body is valid UTF-8");
        assert!(
            body.contains("&lt;script&gt;&amp;&quot;&apos;&lt;/script&gt;"),
            "expected the escaped form in the body, got: {body}"
        );
        assert!(
            !body.contains("<script>"),
            "raw, unescaped input leaked into the body: {body}"
        );
    }

    #[test]
    fn verify_errors_map_to_their_s3_status_and_error_code() {
        assert_eq!(
            S3Error::from(VerifyError::BadSignature).status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(S3Error::from(VerifyError::Expired).code, "ExpiredToken");
        assert_eq!(
            S3Error::from(VerifyError::UnknownAccessKey).code,
            "InvalidAccessKeyId"
        );
    }
}
