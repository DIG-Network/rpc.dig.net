//! The boundary invariant, tested at the HTTP layer.
//!
//! > No write, peer, or control surface is reachable from the anonymous read tier.
//!
//! These tests do something the unit tests cannot: they point the gateway at a node address that
//! **refuses connections**, and then use the response code to tell apart the two things that
//! matter.
//!
//! - A request the gate DENIES never touches the network, so it comes back `-32601`.
//! - A request the gate ALLOWS is forwarded, fails to connect, and comes back `-32603`.
//!
//! So `-32601` here is positive proof that the gateway short-circuited, and `-32603` is positive
//! proof that it really did try to forward. A test that only asserted "the response was an error"
//! would pass either way and prove nothing.

#![cfg(feature = "server")]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use rpc_dig_net::server::{router, Gateway};
use serde_json::{json, Value};
use tower::ServiceExt;

/// Port 1 on loopback: nothing listens, so any forward attempt fails fast and deterministically.
const DEAD_NODE: &str = "http://127.0.0.1:1";

/// Error code returned when the gate refuses without contacting the node.
const DENIED: i64 = -32601;
/// Error code returned when a forwarded call could not reach the node.
const FORWARDED_AND_FAILED: i64 = -32603;

async fn call(req: Request<Body>) -> (StatusCode, Value) {
    let app = router(Gateway::new(DEAD_NODE).expect("gateway"));
    let resp = app.oneshot(req).await.expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

async fn post_rpc(body: Value) -> Value {
    let req = Request::post("/")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("request");
    call(req).await.1
}

fn error_code(body: &Value) -> i64 {
    body["error"]["code"]
        .as_i64()
        .unwrap_or_else(|| panic!("no error code in {body}"))
}

// --- the discriminator that makes every other test meaningful ---------------------------------

/// An ALLOWED method must actually be forwarded. With a dead node that means `-32603`, not
/// `-32601`. If this ever returns `-32601` the gateway has stopped forwarding anything and every
/// "is denied" test below would pass vacuously.
#[tokio::test]
async fn an_allowed_method_is_forwarded_to_the_node() {
    let body = post_rpc(json!({"jsonrpc": "2.0", "id": 1, "method": "dig.getContent"})).await;
    assert_eq!(
        error_code(&body),
        FORWARDED_AND_FAILED,
        "an allowlisted method must reach the forward path"
    );
}

// --- method boundary ---------------------------------------------------------------------------

#[tokio::test]
async fn control_and_peer_methods_never_reach_the_node() {
    for method in [
        "control.status",
        "control.hostedStores.pin",
        "control.config.setUpstream",
        "cache.clear",
        "cache.setCapBytes",
        "dig.getPeers",
        "dig.announce",
        "dig.listInventory",
        "dig.fetchRange",
        "rpc.discover",
    ] {
        let body = post_rpc(json!({"jsonrpc": "2.0", "id": 1, "method": method})).await;
        assert_eq!(error_code(&body), DENIED, "{method} was forwarded");
    }
}

/// Wallet RPC is the sharpest case: the node answers bare method names as wallet operations.
#[tokio::test]
async fn wallet_methods_never_reach_the_node() {
    for method in ["sign", "signMessage", "sendTransaction", "getPublicKeys"] {
        let body = post_rpc(json!({"jsonrpc": "2.0", "id": 1, "method": method})).await;
        assert_eq!(error_code(&body), DENIED, "{method} was forwarded");
    }
}

#[tokio::test]
async fn a_restricted_member_denies_the_whole_batch() {
    let body = post_rpc(json!([
        {"jsonrpc": "2.0", "id": 1, "method": "dig.getContent"},
        {"jsonrpc": "2.0", "id": 2, "method": "control.status"},
    ]))
    .await;
    assert_eq!(error_code(&body), DENIED, "a mixed batch was forwarded");
}

/// DHT and PEX frames are dispatched on body shape, not on a `method` name.
#[tokio::test]
async fn shape_dispatched_peer_frames_never_reach_the_node() {
    for frame in [
        json!({"find_node": {"target": "ab"}}),
        json!({"add_provider": {"key": "ab"}}),
        json!({"pex_handshake": {}}),
    ] {
        let body = post_rpc(frame.clone()).await;
        assert_eq!(error_code(&body), -32600, "{frame} was forwarded");
    }
}

#[tokio::test]
async fn a_non_json_body_is_a_parse_error() {
    let req = Request::post("/")
        .header("content-type", "application/json")
        .body(Body::from("not json at all"))
        .expect("request");
    let (_, body) = call(req).await;
    assert_eq!(error_code(&body), -32700);
}

// --- route boundary ------------------------------------------------------------------------------

/// The node's own paths must not exist on the gateway. `/s/*` is the worst of them: on the node it
/// serves store content ALREADY DECRYPTED server-side.
#[tokio::test]
async fn node_local_paths_are_not_routed() {
    for path in [
        "/s/somestore/index.html",
        "/verify/anything",
        "/ws",
        "/ws/status",
        "/openrpc.json",
        "/.well-known/dig-node.json",
        "/stores/abc/module",
    ] {
        let req = Request::get(path).body(Body::empty()).expect("request");
        let (status, body) = call(req).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path} is routed");
        assert_eq!(body["error"], "not_found", "{path} leaked a response shape");
    }
}

/// The node answers `POST /:method` as wallet RPC. That shape must not be a route here at all.
#[tokio::test]
async fn a_wallet_style_post_path_is_not_routed() {
    for path in ["/sign", "/getPublicKeys", "/sendTransaction"] {
        let req = Request::post(path)
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .expect("request");
        let (status, _) = call(req).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path} is routed");
    }
}

// --- health is answered locally --------------------------------------------------------------

/// The node is dead in these tests, so a healthy `/health` proves the gateway answered it itself.
#[tokio::test]
async fn health_is_answered_locally_and_never_proxied() {
    for path in ["/health", "/"] {
        let req = Request::get(path).body(Body::empty()).expect("request");
        let (status, body) = call(req).await;
        assert_eq!(status, StatusCode::OK, "{path} did not answer");
        assert_eq!(body["status"], "ok");
        assert_eq!(body["service"], "rpc.dig.net");
    }
}

#[tokio::test]
async fn version_reports_the_running_build() {
    let req = Request::get("/version")
        .body(Body::empty())
        .expect("request");
    let (status, body) = call(req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["version"], rpc_dig_net::VERSION);
}

// --- CORS ----------------------------------------------------------------------------------------

#[tokio::test]
async fn cors_allows_any_browser_origin() {
    let req = Request::builder()
        .method("OPTIONS")
        .uri("/")
        .header("origin", "https://example.test")
        .header("access-control-request-method", "POST")
        .body(Body::empty())
        .expect("request");
    let app = router(Gateway::new(DEAD_NODE).expect("gateway"));
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(
        resp.headers()
            .get("access-control-allow-origin")
            .map(|v| v.to_str().unwrap_or_default()),
        Some("*")
    );
}

// --- construction --------------------------------------------------------------------------------

#[test]
fn a_trailing_slash_on_the_node_url_is_normalised() {
    let gw = Gateway::new("http://127.0.0.1:9778/").expect("gateway");
    assert_eq!(gw.node_url(), "http://127.0.0.1:9778");
}
