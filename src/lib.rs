//! `rpc.dig.net` — the public DIG Network read gateway.
//!
//! This crate is the **wrapper**, not the node. A real `dig-node` runs beside it on the same host
//! and owns everything that makes a node a node: the peer ports (`9444` mTLS peer-RPC + DHT,
//! `9445` gossip), the DHT and gossip protocols, and the `.dig` capsule cache. The gateway owns
//! exactly one thing — the **anonymous public read tier** that browsers speak, plain HTTPS + CORS.
//!
//! # Why a strict allowlist and not a reverse proxy
//!
//! The node's local surface on `9778` is designed to be **loopback-only** and is not safe to
//! expose. Alongside the public content reads it also serves a wallet JSON-RPC surface, a wallet
//! WebSocket, and `/s/*` — server-side-DECRYPTED plaintext store content. Forwarding an
//! unrecognised request to it, in any form, is a custody and confidentiality breach.
//!
//! So the gateway is **deny-by-default in both dimensions**:
//!
//! - **Route**: exactly one proxied route, `POST /`. Every other path is answered by the gateway
//!   itself or refused. There is no wildcard, no path pass-through, no "forward the rest".
//! - **Method**: a request body reaches the node only if *every* JSON-RPC call inside it names a
//!   method on the [`PUBLIC_READ_METHODS`] allowlist. A batch is screened element by element —
//!   one denied member denies the whole batch.
//!
//! The gate is a pure function over the request body ([`gate::screen`]) with no I/O, so the
//! boundary invariant is decided in code that a test can exhaustively drive.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod gate;
pub mod jsonrpc;
#[cfg(feature = "server")]
pub mod server;
pub mod tier;

pub use gate::{screen, Verdict};
pub use tier::{tier_of, Tier, PUBLIC_READ_METHODS};

/// The crate version, surfaced on `GET /health` and `GET /version` for build attribution.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
