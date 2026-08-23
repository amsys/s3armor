//! Pooled hyper client, rustls with the webpki root store. One client
//! serves every configured backend — the connector is per-request-URI, not
//! per-host, so there is nothing to pool per-backend (`docs/ARCHITECTURE.md`
//! "Configuration model"; `proxy::forward` picks the target host and credentials per call).

use std::time::Duration;

use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

use super::body::ProxyBody;

pub type BackendClient = Client<HttpsConnector<HttpConnector>, ProxyBody>;

/// Builds the shared backend client. Supports both `http://` (MinIO in
/// local/dev compose files) and `https://` (production — docs/ARCHITECTURE.md "UNSIGNED-PAYLOAD to the backend over TLS" notes TLS
/// to the backend is effectively mandatory there, since payload hashing
/// happens over TLS's own protection, not a second application-layer one).
///
/// `connect_timeout` bounds the TCP+TLS handshake only (`S3A_TIMEOUT_CONNECT`,
/// `docs/ARCHITECTURE.md` "Configuration model") — a hung dial fails instead of blocking a request
/// forever. The response-headers timeout (`S3A_TIMEOUT_REQUEST`) is a
/// per-request concern, applied in `proxy::forward` around the single
/// `client.request(...)` await, not here.
pub fn build(connect_timeout: Duration) -> BackendClient {
    // rustls has no default crypto provider unless exactly one is compiled
    // in; installing it explicitly here means both this client and the
    // server-side `tls` module can rely on it already being set.
    // Safe to re-run: ignore "already installed" from a second caller (tests).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut http = HttpConnector::new();
    http.set_connect_timeout(Some(connect_timeout));
    http.enforce_http(false); // the https:// scheme is layered on top below

    let https = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http);
    Client::builder(TokioExecutor::new()).build(https)
}
