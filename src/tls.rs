//! Origin TLS for the read-tier gateway (dig_ecosystem #1951).
//!
//! CloudFront reaches this gateway over the public internet, so the origin hop must not be
//! plaintext. Not for the payload's sake — DIG content is already ciphertext plus merkle proofs —
//! but because the request path carries `/stores/{store_id}/content/{retrieval_key}`. In the clear
//! that tells any on-path observer exactly which capsule each reader is fetching: a deanonymisation
//! leak about READERS, even though the content itself stays confidential. Provider-blindness is the
//! read tier's whole posture, and a plaintext origin hop re-opens it.
//!
//! Lives in the library rather than in `bin/gateway.rs` so it is TESTABLE. A binary target is a
//! test-free zone — coverage cannot reach it and a mistake in cert handling would be unprovable
//! there. The binary keeps only process wiring.

use std::sync::Arc;

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// Why an origin TLS acceptor could not be built.
#[derive(Debug)]
pub enum TlsError {
    /// The certificate chain could not be read or contained no certificates.
    Cert(String),
    /// The private key could not be read or parsed.
    Key(String),
    /// rustls rejected the chain/key pair (mismatched, unsupported, malformed).
    Config(String),
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsError::Cert(m) => write!(f, "origin certificate: {m}"),
            TlsError::Key(m) => write!(f, "origin private key: {m}"),
            TlsError::Config(m) => write!(f, "origin TLS config: {m}"),
        }
    }
}

impl std::error::Error for TlsError {}

/// Build the origin TLS acceptor from a PEM certificate chain and private key.
///
/// PEM parsing goes through `rustls-pki-types`' own [`PemObject`] trait rather than the separate
/// `rustls-pemfile` crate, which is unmaintained (RUSTSEC-2025-0134) — the same choice dig-relay's
/// `tls.rs` makes, and the reason this crate hand-wires its accept loop instead of using
/// `axum-server`, whose TLS feature depends on it.
///
/// The caller MUST have installed a rustls crypto provider first; rustls 0.23 will not pick one
/// itself, and without it the failure surfaces on the first connection rather than here.
///
/// # Errors
/// [`TlsError`] when the chain is unreadable or empty, the key is unreadable, or rustls rejects the
/// pair. An EMPTY chain is an error rather than an empty-but-valid config: serving with no
/// certificate would fail every handshake at runtime instead of refusing to start.
pub fn build_acceptor(
    cert_path: &str,
    key_path: &str,
) -> Result<tokio_rustls::TlsAcceptor, TlsError> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
        .map_err(|e| TlsError::Cert(format!("{cert_path}: {e}")))?
        .collect::<Result<_, _>>()
        .map_err(|e| TlsError::Cert(format!("{cert_path}: {e}")))?;
    if certs.is_empty() {
        return Err(TlsError::Cert(format!("no certificates in {cert_path}")));
    }

    let key = PrivateKeyDer::from_pem_file(key_path)
        .map_err(|e| TlsError::Key(format!("{key_path}: {e}")))?;

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| TlsError::Config(e.to_string()))?;

    // CloudFront will speak HTTP/2 to an origin that offers it. Advertise both explicitly so the
    // negotiation is a stated choice rather than whatever the default happens to be.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Install the provider once per test process; rustls 0.23 refuses to auto-pick one.
    fn provider() {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    /// `Result::unwrap_err` needs `Debug` on the Ok side and `TlsAcceptor` has none, so unwrap the
    /// error by hand.
    fn expect_err(r: Result<tokio_rustls::TlsAcceptor, TlsError>) -> TlsError {
        match r {
            Err(e) => e,
            Ok(_) => panic!("expected an error, got an acceptor"),
        }
    }

    /// Write a self-signed cert + key pair to a temp dir, returning both paths.
    fn cert_pair(dir: &std::path::Path) -> (String, String) {
        let c = rcgen::generate_simple_self_signed(vec!["node-rpc.dig.net".into()]).unwrap();
        let cert = dir.join("fullchain.pem");
        let key = dir.join("privkey.pem");
        std::fs::write(&cert, c.cert.pem()).unwrap();
        std::fs::write(&key, c.signing_key.serialize_pem()).unwrap();
        (
            cert.to_string_lossy().into_owned(),
            key.to_string_lossy().into_owned(),
        )
    }

    #[test]
    fn builds_an_acceptor_from_a_real_pem_pair() {
        provider();
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = cert_pair(dir.path());
        assert!(build_acceptor(&cert, &key).is_ok());
    }

    #[test]
    fn an_empty_chain_is_refused_at_startup_not_at_first_handshake() {
        // Serving with no certificate would fail every handshake at runtime. Refusing to start is
        // the loud failure; an empty-but-valid config is the silent one.
        provider();
        let dir = tempfile::tempdir().unwrap();
        let (_, key) = cert_pair(dir.path());
        let empty = dir.path().join("empty.pem");
        std::fs::write(&empty, "").unwrap();

        let err = expect_err(build_acceptor(&empty.to_string_lossy(), &key));
        assert!(
            matches!(err, TlsError::Cert(_)),
            "an empty chain must be a Cert error, got {err:?}"
        );
    }

    #[test]
    fn a_missing_certificate_file_is_a_cert_error() {
        provider();
        let dir = tempfile::tempdir().unwrap();
        let (_, key) = cert_pair(dir.path());
        let err = expect_err(build_acceptor("/nonexistent/fullchain.pem", &key));
        assert!(matches!(err, TlsError::Cert(_)), "got {err:?}");
    }

    #[test]
    fn a_missing_key_file_is_a_key_error() {
        // Distinguished from the cert error so the operator is told WHICH half is wrong — the two
        // have different remedies and certbot writes them to different paths.
        provider();
        let dir = tempfile::tempdir().unwrap();
        let (cert, _) = cert_pair(dir.path());
        let err = expect_err(build_acceptor(&cert, "/nonexistent/privkey.pem"));
        assert!(matches!(err, TlsError::Key(_)), "got {err:?}");
    }

    #[test]
    fn garbage_in_the_key_file_is_a_key_error_not_a_panic() {
        provider();
        let dir = tempfile::tempdir().unwrap();
        let (cert, _) = cert_pair(dir.path());
        let bad = dir.path().join("bad.pem");
        std::fs::write(&bad, "-----BEGIN PRIVATE KEY-----\nnot base64\n").unwrap();
        let err = expect_err(build_acceptor(&cert, &bad.to_string_lossy()));
        assert!(matches!(err, TlsError::Key(_)), "got {err:?}");
    }

    #[test]
    fn the_error_text_names_the_offending_path() {
        // The operator debugging a failed start needs to know which file, not just "TLS error".
        provider();
        let dir = tempfile::tempdir().unwrap();
        let (_, key) = cert_pair(dir.path());
        let err = expect_err(build_acceptor("/nonexistent/chain.pem", &key));
        assert!(
            err.to_string().contains("/nonexistent/chain.pem"),
            "got {err}"
        );
    }
}
