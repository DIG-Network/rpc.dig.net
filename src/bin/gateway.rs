//! The `rpc.dig.net` gateway process.
//!
//! Runs beside a real `dig-node` on the same host and publishes exactly one thing to the world:
//! the anonymous public read tier. Listens on `GATEWAY_LISTEN` (default `0.0.0.0:8080`, behind
//! CloudFront) and forwards screened JSON-RPC to the node's loopback surface at `DIG_NODE_URL`
//! (default `http://127.0.0.1:9778`).
//!
//! The route table and the tier gate live in the library (`rpc_dig_net::server`,
//! `rpc_dig_net::gate`) so they can be tested; this file is only process wiring.

use std::net::SocketAddr;

use rpc_dig_net::server::{router, Gateway};
use rpc_dig_net::VERSION;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let listen: SocketAddr = std::env::var("GATEWAY_LISTEN")
        .unwrap_or_else(|_| "0.0.0.0:8080".into())
        .parse()?;
    let node_url = std::env::var("DIG_NODE_URL").unwrap_or_else(|_| "http://127.0.0.1:9778".into());

    let gateway = Gateway::new(node_url)?;
    tracing::info!(%listen, node = %gateway.node_url(), version = VERSION, "rpc.dig.net gateway up");

    // TLS is served HERE, at the origin, when a cert pair is configured (#1951).
    //
    // CloudFront reaches this box over the public internet, so the hop must not be plaintext — not
    // because the payload needs it (DIG content is already ciphertext + merkle proofs) but because
    // the REQUEST PATH carries `/stores/{store_id}/content/{retrieval_key}`. In the clear that tells
    // any on-path observer exactly which capsule each reader is fetching: a deanonymisation leak
    // about readers, even though the content stays confidential. Provider-blindness is the read
    // tier's whole posture and a plaintext origin hop re-opens it.
    //
    // Unset (both empty) keeps plain HTTP, which is what the local tests and a dev run use.
    let cert = std::env::var("GATEWAY_TLS_CERT").unwrap_or_default();
    let key = std::env::var("GATEWAY_TLS_KEY").unwrap_or_default();

    if cert.is_empty() || key.is_empty() {
        tracing::warn!("no GATEWAY_TLS_CERT/KEY — serving plain HTTP (dev only)");
        let listener = tokio::net::TcpListener::bind(listen).await?;
        axum::serve(listener, router(gateway))
            .with_graceful_shutdown(shutdown_signal())
            .await?;
        return Ok(());
    }

    // rustls 0.23 refuses to auto-pick a provider when more than one could be linked, so install
    // ring explicitly before any TLS use — otherwise this panics at first connection rather than
    // failing at startup, which is the worse failure to debug on a live origin.
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| "could not install the rustls ring provider")?;

    let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert, &key).await?;
    tracing::info!(cert = %cert, "origin TLS enabled");
    axum_server::bind_rustls(listen, tls)
        .serve(router(gateway).into_make_service())
        .await?;
    Ok(())
}

/// Resolve on Ctrl-C / SIGTERM so in-flight requests drain on a deploy.
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
