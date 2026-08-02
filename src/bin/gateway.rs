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

    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, router(gateway))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

/// Resolve on Ctrl-C / SIGTERM so in-flight requests drain on a deploy.
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
