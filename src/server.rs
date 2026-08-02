//! The HTTP surface: routes, CORS, limits, and the loopback forward.
//!
//! This lives in the library rather than in `main` so the boundary can be driven by tests. The
//! interesting properties are not "does the gate function return the right enum" — [`crate::gate`]
//! covers that — but "does an unmatched path reach the node", "is `/health` really answered
//! locally", "does a denied method produce a reply without any upstream call at all". Those are
//! properties of the wiring, and the wiring is only testable if it is a value you can construct.

use std::time::Duration;

use axum::{
    extract::State,
    http::{HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use tower_http::cors::{Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;

use crate::{screen, Verdict, VERSION};

/// Largest JSON-RPC request body accepted, in bytes.
///
/// Read requests carry ids, roots and ranges — kilobytes at most. A generous ceiling that still
/// refuses a body big enough to be a memory-pressure lever.
pub const MAX_BODY_BYTES: usize = 256 * 1024;

/// How long a single upstream node call may take before the gateway gives up.
pub const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(25);

/// Whole-request deadline, above [`UPSTREAM_TIMEOUT`] so the upstream timeout is what a caller
/// normally observes and this is only a backstop.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Shared handles for the request path.
#[derive(Clone)]
pub struct Gateway {
    http: reqwest::Client,
    /// Base URL of the dig-node this gateway wraps. Must be loopback in production.
    node_url: String,
}

impl Gateway {
    /// Build a gateway pointed at `node_url`.
    ///
    /// # Errors
    /// If the HTTP client cannot be constructed (a TLS backend failure).
    pub fn new(node_url: impl Into<String>) -> Result<Self, reqwest::Error> {
        Ok(Self {
            http: reqwest::Client::builder()
                .timeout(UPSTREAM_TIMEOUT)
                .build()?,
            node_url: node_url.into().trim_end_matches('/').to_string(),
        })
    }

    /// The node URL this gateway forwards to.
    pub fn node_url(&self) -> &str {
        &self.node_url
    }
}

/// The complete public route table.
///
/// `POST /` is the only route that reaches the node, and only after [`screen`] allows the body.
/// `/health` and `/version` are answered here and never proxied — a liveness probe must not be a
/// path to the node. [`Router::fallback`] answers every other path locally; there is deliberately
/// no wildcard and no proxy-the-rest arm, because the node's own surface also serves wallet RPC
/// and server-side-decrypted plaintext.
pub fn router(state: Gateway) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::POST, Method::GET, Method::OPTIONS])
        .allow_headers(Any)
        .max_age(Duration::from_secs(86_400));

    Router::new()
        .route("/", post(rpc).get(health))
        .route("/health", get(health))
        .route("/version", get(version))
        .fallback(not_found)
        .layer(cors)
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        // 504, not the default 408: a deadline hit here means the node behind us did not answer
        // in time, which is a gateway-timeout condition, not a slow client.
        .layer(TimeoutLayer::with_status_code(
            StatusCode::GATEWAY_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
        .with_state(state)
}

/// `POST /` — screen, then forward or refuse.
async fn rpc(
    State(gw): State<Gateway>,
    body: Result<Json<Value>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(b) => b,
        // A body that is not JSON at all never gets a tier decision — it is a parse error.
        Err(_) => return rpc_error(-32700, "parse error"),
    };

    if let Verdict::Deny { code, message } = screen(&body) {
        // Debug, not info: a refused method name is caller-controlled input, and a public endpoint
        // should not let a caller write arbitrary strings into the default log stream.
        tracing::debug!(code, message, "request denied at the tier gate");
        return rpc_error(code, message);
    }

    forward(&gw, &body).await
}

/// Forward an allowed body to the node verbatim and relay its JSON reply.
async fn forward(gw: &Gateway, body: &Value) -> Response {
    match gw.http.post(&gw.node_url).json(body).send().await {
        Ok(resp) => match resp.json::<Value>().await {
            Ok(v) => (StatusCode::OK, Json(v)).into_response(),
            Err(e) => {
                tracing::warn!(error = %e, "node reply was not JSON");
                rpc_error(-32603, "internal error")
            }
        },
        Err(e) => {
            tracing::warn!(error = %e, "node unreachable");
            rpc_error(-32603, "internal error")
        }
    }
}

/// `GET /health` — the gateway's own liveness. Answered locally; never proxied.
async fn health() -> Response {
    (
        StatusCode::OK,
        Json(json!({ "status": "ok", "service": "rpc.dig.net", "version": VERSION })),
    )
        .into_response()
}

/// `GET /version` — build attribution for bug reports (CLAUDE.md §6.7).
async fn version() -> Response {
    (StatusCode::OK, Json(json!({ "version": VERSION }))).into_response()
}

/// Any unmatched path. Deliberately a flat 404 that names no upstream and hints at no other
/// surface.
async fn not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({ "error": "not_found", "message": "unknown route" })),
    )
        .into_response()
}

/// A JSON-RPC 2.0 error object with HTTP 200, as the spec requires for a well-formed transport.
fn rpc_error(code: i32, message: &str) -> Response {
    let mut resp = (
        StatusCode::OK,
        Json(json!({
            "jsonrpc": "2.0",
            "id": Value::Null,
            "error": { "code": code, "message": message, "data": { "origin": "rpc.dig.net" } }
        })),
    )
        .into_response();
    resp.headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    resp
}
