//! TLS listener support: loads `S3A_TLS_CERT`/`S3A_TLS_KEY` PEM files into a
//! `rustls::ServerConfig`, and a matching client verifier for the loopback
//! health-probe. `docs/ARCHITECTURE.md` "S3 operation matrix (v1)"/"Configuration model"; originally deferred, built here
//! since most deployments now want it rather than a reverse proxy.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("cannot read {0}: {1}")]
    Read(String, io::Error),
    #[error("no certificate found in {0}")]
    NoCert(String),
    #[error("invalid PEM in {0}: {1}")]
    Parse(String, rustls::pki_types::pem::Error),
    #[error("building TLS server config: {0}")]
    Config(rustls::Error),
}

/// Loads a cert chain + private key from PEM files and builds a
/// `rustls::ServerConfig` for the S3 listener. Called once at startup —
/// `main::serve` exits loudly on failure, same posture as a bad config var.
pub fn load_server_config(cert_path: &str, key_path: &str) -> Result<Arc<ServerConfig>, TlsError> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(TlsError::Config)?;
    Ok(Arc::new(config))
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let bytes = std::fs::read(path).map_err(|e| TlsError::Read(path.to_string(), e))?;
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<_, _>>()
        .map_err(|e| TlsError::Parse(path.to_string(), e))?;
    if certs.is_empty() {
        return Err(TlsError::NoCert(path.to_string()));
    }
    Ok(certs)
}

fn load_key(path: &str) -> Result<PrivateKeyDer<'static>, TlsError> {
    let bytes = std::fs::read(path).map_err(|e| TlsError::Read(path.to_string(), e))?;
    // `from_pem_slice` folds "PEM parsed, no key in it" into the same
    // `NoItemsFound` error as "not PEM at all" — both are `Parse` here,
    // unlike `load_certs`'s empty check, since there is no distinct empty
    // success value to check for the way `certs.is_empty()` does.
    PrivateKeyDer::from_pem_slice(&bytes).map_err(|e| TlsError::Parse(path.to_string(), e))
}

/// A plain or TLS-wrapped TCP connection, so `main::serve`'s accept loop can
/// hand either kind to hyper through one code path instead of duplicating
/// the whole per-connection block for the TLS case.
pub enum Conn {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for Conn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Conn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            Self::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// A certificate verifier that accepts anything — used **only** by
/// `health-probe` to connect to `127.0.0.1` over TLS, where the configured
/// certificate's hostname will never match. Not a weakening: the probe
/// authenticates nothing and carries no secret, it only asks whether this
/// process still answers `/health` on its own configured port.
#[derive(Debug)]
pub struct AcceptAnyServerCert(pub Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
        .map(|_| rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
        .map(|_| rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny self-signed cert/key pair, generated once and embedded, so
    /// this test needs no `openssl` on the machine running `cargo test`.
    /// Regenerate with:
    ///   openssl req -x509 -newkey ed25519 -nodes -keyout key.pem \
    ///     -out cert.pem -days 3650 -subj "/CN=test"
    const TEST_CERT: &str = include_str!("../testdata/tls/test-cert.pem");
    const TEST_KEY: &str = include_str!("../testdata/tls/test-key.pem");

    fn write_temp(name: &str, contents: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "s3a-tls-test-{name}-{:?}",
            std::thread::current().id()
        ));
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn loads_valid_cert_and_key() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert_path = write_temp("cert", TEST_CERT);
        let key_path = write_temp("key", TEST_KEY);
        let result = load_server_config(cert_path.to_str().unwrap(), key_path.to_str().unwrap());
        assert!(result.is_ok(), "{:?}", result.err());
        std::fs::remove_file(cert_path).ok();
        std::fs::remove_file(key_path).ok();
    }

    #[test]
    fn missing_cert_file_errors() {
        let err = load_server_config("/nonexistent/cert.pem", "/nonexistent/key.pem");
        assert!(matches!(err, Err(TlsError::Read(_, _))));
    }

    #[test]
    fn empty_cert_file_errors() {
        let cert_path = write_temp("empty-cert", "");
        let key_path = write_temp("key2", TEST_KEY);
        let err = load_server_config(cert_path.to_str().unwrap(), key_path.to_str().unwrap());
        assert!(matches!(err, Err(TlsError::NoCert(_))));
        std::fs::remove_file(cert_path).ok();
        std::fs::remove_file(key_path).ok();
    }
}
