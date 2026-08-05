//! The path-addressed content read (`GET /stores/:id/content/:rk`, #2000), tested against a real
//! stub node over loopback.
//!
//! These are not symmetric-mock tests: the stub speaks the actual `dig.getContent` window wire
//! (base64 ciphertext, base64 inclusion proof, a `chunk_lens` array, `complete`/`next_offset`), and
//! the assertions are about the gateway's TRANSLATION of that wire into an HTTP envelope — the raw
//! ciphertext body, the pinned `X-Dig-*`/CORS header set, the full-200 range slice, and the
//! security properties that make this route safe to expose: the decoy is indistinguishable from a
//! real hit, a range is fetched range-scoped (never buffering the whole resource), an over-size read
//! is refused, no error is ever cached, and no inbound auth header crosses the loopback.

#![cfg(feature = "server")]

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use base64::Engine as _;
use http_body_util::BodyExt;
use rpc_dig_net::server::{router, Gateway};
use serde_json::{json, Value};
use tower::ServiceExt;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// A 64-hex fixture value (a stand-in 32-byte hash). `c` MUST be a hex digit.
fn hex64(c: char) -> String {
    c.to_string().repeat(64)
}

// -- The stub node --------------------------------------------------------------------------------

/// How the stub picks a reply for a forwarded `dig.getContent` call.
enum Replies {
    /// One reply per call, in order (the gateway pages sequentially).
    Ordered(Vec<Value>),
    /// Reply keyed by the request's `offset` param; a request for an absent offset panics the stub,
    /// which is exactly how the range-scoping test proves no out-of-range window was ever fetched.
    ByOffset(HashMap<u64, Value>),
}

struct StubState {
    replies: Replies,
    calls: AtomicUsize,
    /// Every `offset` the gateway asked the node for — the range-scoping probe.
    seen_offsets: Mutex<Vec<u64>>,
    /// The `Authorization` header seen on each forwarded request (`None` if absent) — the leak probe.
    seen_auth: Mutex<Vec<Option<String>>>,
    /// The `Cookie` header seen on each forwarded request.
    seen_cookie: Mutex<Vec<Option<String>>>,
}

async fn stub_handler(
    State(st): State<Arc<StubState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    st.seen_auth.lock().unwrap().push(
        headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string),
    );
    st.seen_cookie.lock().unwrap().push(
        headers
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string),
    );
    let offset = body["params"]["offset"].as_u64().unwrap_or(0);
    st.seen_offsets.lock().unwrap().push(offset);
    let idx = st.calls.fetch_add(1, Ordering::SeqCst);
    let reply = match &st.replies {
        Replies::Ordered(v) => v
            .get(idx)
            .cloned()
            .unwrap_or_else(|| v.last().cloned().expect("stub has a reply")),
        Replies::ByOffset(map) => map
            .get(&offset)
            .cloned()
            .unwrap_or_else(|| panic!("stub asked for an unexpected offset {offset}")),
    };
    Json(reply)
}

async fn spawn(replies: Replies) -> (String, Arc<StubState>) {
    let state = Arc::new(StubState {
        replies,
        calls: AtomicUsize::new(0),
        seen_offsets: Mutex::new(Vec::new()),
        seen_auth: Mutex::new(Vec::new()),
        seen_cookie: Mutex::new(Vec::new()),
    });
    let app = Router::new()
        .route("/", post(stub_handler))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stub");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve stub");
    });
    (format!("http://{addr}"), state)
}

async fn spawn_stub(replies: Vec<Value>) -> (String, Arc<StubState>) {
    spawn(Replies::Ordered(replies)).await
}

/// Build one `dig.getContent` reply carrying `result`.
fn window(
    ciphertext: &[u8],
    root: &str,
    complete: bool,
    next_offset: Option<u64>,
    proof: Option<&str>,
    chunk_lens: Option<&[u32]>,
) -> Value {
    let mut result = json!({
        "ciphertext": B64.encode(ciphertext),
        "root": root,
        "complete": complete,
    });
    if let Some(n) = next_offset {
        result["next_offset"] = json!(n);
    }
    if let Some(p) = proof {
        result["inclusion_proof"] = json!(p);
    }
    if let Some(cl) = chunk_lens {
        result["chunk_lens"] = json!(cl);
    }
    json!({ "jsonrpc": "2.0", "id": 1, "result": result })
}

/// Issue the content GET through the real gateway router pointed at `node_url`.
async fn content_get(
    node_url: &str,
    store: &str,
    rk: &str,
    query: &str,
    extra_headers: &[(&str, &str)],
) -> axum::response::Response {
    let app = router(Gateway::new(node_url).expect("gateway"));
    let uri = format!("/stores/{store}/content/{rk}{query}");
    let mut builder = Request::get(uri);
    for (k, v) in extra_headers {
        builder = builder.header(*k, *v);
    }
    let req = builder.body(Body::empty()).expect("request");
    app.oneshot(req).await.expect("response")
}

fn header(resp: &axum::response::Response, name: &str) -> Option<String> {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// The sorted set of header NAMES on a response — the shape a decoy must not diverge from.
fn header_names(resp: &axum::response::Response) -> Vec<String> {
    let mut ns: Vec<String> = resp
        .headers()
        .keys()
        .map(|k| k.as_str().to_string())
        .collect();
    ns.sort();
    ns
}

async fn body_bytes(resp: axum::response::Response) -> Vec<u8> {
    resp.into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes()
        .to_vec()
}

/// Every error path MUST carry `cache-control: no-store` and MUST NEVER carry the immutable
/// directive (security Finding 1 — an error frozen into the 1-year cache is a poisoning vector).
fn assert_no_immutable_error(resp: &axum::response::Response) {
    let cc = header(resp, "cache-control");
    assert_eq!(cc.as_deref(), Some("no-store"), "error must be no-store");
    assert!(
        !cc.unwrap_or_default().contains("immutable"),
        "an error must never be cached immutably"
    );
}

// -- Envelope translation -------------------------------------------------------------------------

#[tokio::test]
async fn a_single_window_becomes_raw_ciphertext_with_the_pinned_headers() {
    let root = hex64('a');
    let rk = hex64('b');
    let store = hex64('c');
    let cipher = b"the-immutable-ciphertext-bytes";
    let proof = B64.encode(b"merkle-inclusion-proof");
    // Multi-chunk so x-dig-chunk-lens is present; total-length = 10+20 = 30.
    let (node, _st) = spawn_stub(vec![window(
        cipher,
        &root,
        true,
        None,
        Some(&proof),
        Some(&[10, 20]),
    )])
    .await;

    let resp = content_get(&node, &store, &rk, &format!("?root={root}"), &[]).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        header(&resp, "content-type").as_deref(),
        Some("application/octet-stream")
    );
    assert_eq!(
        header(&resp, "cache-control").as_deref(),
        Some("public, max-age=31536000, immutable")
    );
    // content-length = sum(chunk_lens) = total ciphertext bytes (10+20), the same value as
    // x-dig-total-length, and it MUST equal the streamed body length.
    assert_eq!(header(&resp, "content-length").as_deref(), Some("30"));
    assert_eq!(header(&resp, "x-dig-total-length").as_deref(), Some("30"));
    assert_eq!(
        header(&resp, "x-dig-inclusion-proof").as_deref(),
        Some(proof.as_str())
    );
    assert_eq!(header(&resp, "x-dig-chunk-lens").as_deref(), Some("10,20"));

    // The retired Lambda set NEITHER of these on the content GET — the URL is content-addressed.
    assert!(
        header(&resp, "x-dig-root").is_none(),
        "x-dig-root must be absent"
    );
    assert!(header(&resp, "etag").is_none(), "ETag must be absent");
    assert!(
        header(&resp, "accept-ranges").is_none(),
        "Accept-Ranges must be absent (full-200 slice, no 206)"
    );

    assert_eq!(body_bytes(resp).await, cipher);
}

/// The FULL pinned header set the hub service worker + the retired Lambda agree on. Formerly the
/// PIN-pending golden stub; now filled and load-bearing.
#[tokio::test]
async fn golden_header_set_matches_the_dighub_retrieval_lambda() {
    let root = hex64('a');
    let rk = hex64('b');
    let store = hex64('c');
    let proof = B64.encode(b"golden-proof");
    let (node, _st) = spawn_stub(vec![window(
        b"golden-body",
        &root,
        true,
        None,
        Some(&proof),
        Some(&[6, 5]),
    )])
    .await;

    let resp = content_get(&node, &store, &rk, &format!("?root={root}"), &[]).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Present, exactly:
    assert_eq!(
        header(&resp, "content-type").as_deref(),
        Some("application/octet-stream")
    );
    assert_eq!(
        header(&resp, "cache-control").as_deref(),
        Some("public, max-age=31536000, immutable")
    );
    assert_eq!(
        header(&resp, "access-control-allow-origin").as_deref(),
        Some("*")
    );
    assert_eq!(
        header(&resp, "access-control-expose-headers").as_deref(),
        Some("x-dig-inclusion-proof, x-dig-chunk-lens, x-dig-total-length")
    );
    assert_eq!(header(&resp, "x-dig-total-length").as_deref(), Some("11"));
    // content-length = sum(chunk_lens) = the ciphertext byte count (6+5), matching the body.
    assert_eq!(header(&resp, "content-length").as_deref(), Some("11"));
    assert_eq!(
        header(&resp, "x-dig-inclusion-proof").as_deref(),
        Some(proof.as_str())
    );
    assert_eq!(header(&resp, "x-dig-chunk-lens").as_deref(), Some("6,5"));

    // Absent, exactly:
    for forbidden in ["x-dig-root", "etag", "accept-ranges", "content-range"] {
        assert!(
            header(&resp, forbidden).is_none(),
            "{forbidden} must not be set on the content GET"
        );
    }
}

#[tokio::test]
async fn a_single_chunk_resource_omits_chunk_lens_but_keeps_total_length() {
    let root = hex64('a');
    let rk = hex64('b');
    let store = hex64('c');
    let (node, _st) =
        spawn_stub(vec![window(b"single", &root, true, None, None, Some(&[6]))]).await;

    let resp = content_get(&node, &store, &rk, &format!("?root={root}"), &[]).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(header(&resp, "x-dig-total-length").as_deref(), Some("6"));
    assert!(
        header(&resp, "x-dig-chunk-lens").is_none(),
        "single-chunk resource must not emit x-dig-chunk-lens"
    );
}

// -- root / address validation (never cached) -----------------------------------------------------

#[tokio::test]
async fn a_missing_or_malformed_root_is_a_400_that_is_never_cached() {
    let rk = hex64('b');
    let store = hex64('c');
    let dead = "http://127.0.0.1:1";

    for query in [
        "".to_string(),
        "?root=abcd".to_string(),
        format!("?root={}", "z".repeat(64)),
    ] {
        let resp = content_get(dead, &store, &rk, &query, &[]).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "query {query:?}");
        assert_no_immutable_error(&resp);
    }
}

#[tokio::test]
async fn a_malformed_store_id_or_rk_is_a_400() {
    let root = hex64('a');
    let dead = "http://127.0.0.1:1";
    let resp = content_get(dead, "abc", &hex64('b'), &format!("?root={root}"), &[]).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bad_rk = "x".repeat(64);
    let resp = content_get(dead, &hex64('c'), &bad_rk, &format!("?root={root}"), &[]).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// -- Range is full-200 slice (no 206, no 416) -----------------------------------------------------

#[tokio::test]
async fn a_byte_range_yields_200_and_the_sliced_body() {
    let root = hex64('a');
    let rk = hex64('b');
    let store = hex64('c');
    let cipher: Vec<u8> = (0u8..30).collect();
    // Range starts at 0, so the offset-0 window covers it in one call.
    let (node, _st) = spawn_stub(vec![window(&cipher, &root, true, None, None, Some(&[30]))]).await;

    let resp = content_get(
        &node,
        &store,
        &rk,
        &format!("?root={root}"),
        &[("range", "bytes=0-9")],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "range is 200, never 206");
    assert!(header(&resp, "content-range").is_none());
    assert!(header(&resp, "accept-ranges").is_none());
    let body = body_bytes(resp).await;
    assert_eq!(body.len(), 10);
    assert_eq!(body, &cipher[0..10]);
}

#[tokio::test]
async fn an_out_of_range_start_is_200_with_an_empty_body() {
    let root = hex64('a');
    let rk = hex64('b');
    let store = hex64('c');
    // A request for offset 100 on a 10-byte resource: the node returns an empty, complete window.
    let mut by_offset = HashMap::new();
    by_offset.insert(100u64, window(b"", &root, true, None, None, None));
    let (node, _st) = spawn(Replies::ByOffset(by_offset)).await;

    let resp = content_get(
        &node,
        &store,
        &rk,
        &format!("?root={root}"),
        &[("range", "bytes=100-200")],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_bytes(resp).await, Vec::<u8>::new());
}

/// RANGE-SCOPED FETCH: a range starting mid-resource must fetch ONLY the overlapping windows and
/// NEVER offset 0 (adversarial Break 1 / security Finding 2 — the whole-resource buffer is a
/// memory-amplification DoS). The stub panics if asked for any offset but the covering window.
#[tokio::test]
async fn a_range_fetches_only_the_overlapping_windows() {
    let root = hex64('a');
    let rk = hex64('b');
    let store = hex64('c');
    // The covering window at offset 1000 returns [1000,1100), complete — one call, no offset 0.
    let cover: Vec<u8> = (0u8..100).collect();
    let mut by_offset = HashMap::new();
    by_offset.insert(1000u64, window(&cover, &root, true, None, None, None));
    // Deliberately NO entry for offset 0: any attempt to fetch it panics the stub.
    let (node, st) = spawn(Replies::ByOffset(by_offset)).await;

    let resp = content_get(
        &node,
        &store,
        &rk,
        &format!("?root={root}"),
        &[("range", "bytes=1000-1099")],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_bytes(resp).await.len(), 100);

    let offsets = st.seen_offsets.lock().unwrap().clone();
    assert_eq!(offsets, vec![1000], "must fetch only the covering window");
    assert!(
        !offsets.contains(&0),
        "offset 0 must never be fetched for a mid-range"
    );
}

// -- The decoy is indistinguishable from a real hit (whole AND range) ----------------------------

/// A missing/unauthorized key — even one the node reports with `-32004` — must come back as a `200`
/// carrying the node's constant-time decoy, NEVER a `404`, with no status/length/header-set
/// divergence from a real hit. Covers BOTH a whole read and a range read.
#[tokio::test]
async fn a_decoy_is_indistinguishable_from_a_real_hit_whole_and_range() {
    let root = hex64('a');
    let rk = hex64('b');
    let store = hex64('c');
    let proof = B64.encode(b"proof-shaped-blob-16");

    let real_cipher = b"REAL-content-bytes--"; // 20 bytes
    let decoy_cipher = b"DECOY-constant-time-"; // 20 bytes, same length

    let real_window = || window(real_cipher, &root, true, None, Some(&proof), Some(&[20]));
    let decoy_window = || {
        let mut w = window(decoy_cipher, &root, true, None, Some(&proof), Some(&[20]));
        w["error"] = json!({ "code": -32004, "message": "resource not available" });
        w
    };

    for (label, query, headers) in [
        ("whole", format!("?root={root}"), Vec::new()),
        (
            "range",
            format!("?root={root}"),
            vec![("range", "bytes=0-9")],
        ),
    ] {
        let (real_node, _r) = spawn_stub(vec![real_window()]).await;
        let real = content_get(&real_node, &store, &rk, &query, &headers).await;
        let (decoy_node, _d) = spawn_stub(vec![decoy_window()]).await;
        let decoy = content_get(&decoy_node, &store, &rk, &query, &headers).await;

        assert_eq!(real.status(), StatusCode::OK, "{label}: real");
        assert_eq!(decoy.status(), StatusCode::OK, "{label}: decoy is 200");
        assert_ne!(decoy.status(), StatusCode::NOT_FOUND, "{label}: never 404");
        assert_eq!(
            header_names(&real),
            header_names(&decoy),
            "{label}: header-set parity"
        );

        let real_body = body_bytes(real).await;
        let decoy_body = body_bytes(decoy).await;
        assert_eq!(real_body.len(), decoy_body.len(), "{label}: length parity");
    }
}

// -- Paging (range-scoped, still assembles across windows) ---------------------------------------

#[tokio::test]
async fn multiple_windows_assemble_into_the_whole_resource() {
    let root = hex64('a');
    let rk = hex64('b');
    let store = hex64('c');
    let proof = B64.encode(b"first-window-proof");
    let w0 = b"first-window-";
    let w1 = b"second-window-";
    let w2 = b"third-window";
    // chunk_lens (ciphertext byte lengths) MUST sum to the total streamed body: 13 + 14 + 12 = 39.
    let replies = vec![
        window(
            w0,
            &root,
            false,
            Some(13),
            Some(&proof),
            Some(&[13, 14, 12]),
        ),
        window(w1, &root, false, Some(27), None, None),
        window(w2, &root, true, None, None, None),
    ];
    let (node, st) = spawn_stub(replies).await;

    let resp = content_get(&node, &store, &rk, &format!("?root={root}"), &[]).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        header(&resp, "x-dig-inclusion-proof").as_deref(),
        Some(proof.as_str())
    );
    assert_eq!(
        header(&resp, "x-dig-chunk-lens").as_deref(),
        Some("13,14,12")
    );
    assert_eq!(header(&resp, "x-dig-total-length").as_deref(), Some("39"));
    assert_eq!(header(&resp, "content-length").as_deref(), Some("39"));

    let mut expected = Vec::new();
    expected.extend_from_slice(w0);
    expected.extend_from_slice(w1);
    expected.extend_from_slice(w2);
    assert_eq!(body_bytes(resp).await, expected);
    assert_eq!(
        st.calls.load(Ordering::SeqCst),
        3,
        "should page all windows"
    );
}

// -- Header hygiene: no auth leakage over the loopback -------------------------------------------

#[tokio::test]
async fn inbound_auth_headers_are_not_forwarded_to_the_node() {
    let root = hex64('a');
    let rk = hex64('b');
    let store = hex64('c');
    let (node, st) = spawn_stub(vec![window(b"x", &root, true, None, None, Some(&[1]))]).await;

    let resp = content_get(
        &node,
        &store,
        &rk,
        &format!("?root={root}"),
        &[
            ("authorization", "Bearer secret-token"),
            ("cookie", "session=abc123"),
        ],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    assert!(
        st.seen_auth.lock().unwrap().iter().all(Option::is_none),
        "an Authorization header leaked to the node"
    );
    assert!(
        st.seen_cookie.lock().unwrap().iter().all(Option::is_none),
        "a Cookie header leaked to the node"
    );
}

// -- Upstream failures (never cached, never 404) -------------------------------------------------

#[tokio::test]
async fn a_dead_node_is_a_502_that_is_never_cached() {
    let root = hex64('a');
    let resp = content_get(
        "http://127.0.0.1:1",
        &hex64('c'),
        &hex64('b'),
        &format!("?root={root}"),
        &[],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    assert_no_immutable_error(&resp);
}

#[tokio::test]
async fn a_reply_with_no_window_is_a_502_not_a_404() {
    let root = hex64('a');
    let bare_error =
        json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": -32004, "message": "x" }});
    let (node, _st) = spawn_stub(vec![bare_error]).await;
    let resp = content_get(
        &node,
        &hex64('c'),
        &hex64('b'),
        &format!("?root={root}"),
        &[],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    assert_ne!(resp.status(), StatusCode::NOT_FOUND);
    assert_no_immutable_error(&resp);
}

// -- Streaming: no size cap, no 413 holdings oracle, bounded per-step memory ---------------------

/// A whole read LARGER than the old 64 MiB cap MUST stream a `200` with the full body — there is no
/// `413` any more, because a size-dependent status was a holdings oracle (a held resource > cap →
/// `413` while a not-held key → `200` decoy). This drives 65 windows of 1 MiB (65 MiB > 64 MiB).
#[tokio::test]
async fn a_large_whole_read_streams_200_never_413() {
    let root = hex64('a');
    let rk = hex64('b');
    let store = hex64('c');
    let win_bytes: Vec<u8> = vec![7u8; 1024 * 1024];
    let count: u64 = 65;
    // chunk_lens on the first window must sum to the whole ciphertext byte count so content-length
    // matches the streamed body (65 MiB fits comfortably in a u32).
    let total_len: u32 = (count as u32) * 1024 * 1024;
    let mut replies = Vec::new();
    for i in 0..count {
        let last = i == count - 1;
        replies.push(window(
            &win_bytes,
            &root,
            last,
            if last {
                None
            } else {
                Some((i + 1) * 1024 * 1024)
            },
            if i == 0 { Some("cAo=") } else { None },
            if i == 0 {
                Some(std::slice::from_ref(&total_len))
            } else {
                None
            },
        ));
    }
    let (node, _st) = spawn_stub(replies).await;

    let resp = content_get(&node, &store, &rk, &format!("?root={root}"), &[]).await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "a large read is 200, never 413"
    );
    assert_ne!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let body = body_bytes(resp).await;
    assert_eq!(
        body.len(),
        (count as usize) * 1024 * 1024,
        "full body streamed"
    );
}

/// The body is streamed LAZILY — only the first window is fetched before the response is returned,
/// and later windows are pulled as the body is consumed. This is the property that bounds memory to
/// ~one window without a cap: at header time exactly one node call has happened.
#[tokio::test]
async fn the_body_is_streamed_lazily_one_window_at_a_time() {
    let root = hex64('a');
    let rk = hex64('b');
    let store = hex64('c');
    let replies = vec![
        window(b"AAAA", &root, false, Some(4), Some("cAo="), Some(&[12])),
        window(b"BBBB", &root, false, Some(8), None, None),
        window(b"CCCC", &root, true, None, None, None),
    ];
    let (node, st) = spawn_stub(replies).await;

    // Get the response (headers) WITHOUT consuming the body.
    let resp = content_get(&node, &store, &rk, &format!("?root={root}"), &[]).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        st.calls.load(Ordering::SeqCst),
        1,
        "only the first window is fetched before the body is consumed"
    );

    // Now drain the body; the remaining windows are pulled lazily as it streams.
    let body = body_bytes(resp).await;
    assert_eq!(body, b"AAAABBBBCCCC");
    assert_eq!(
        st.calls.load(Ordering::SeqCst),
        3,
        "all windows fetched only once the body was fully consumed"
    );
}

/// A mid-stream upstream failure on an INCOMPLETE resource MUST abort the body (yield an error), NOT
/// end it cleanly — a clean chunked EOF on a truncated, immutable `200` would be cached forever as a
/// complete-but-short ciphertext (a cache-poisoning bug the streaming rewrite introduced). The status
/// is still `200` (committed before the fault), but the body read MUST error so no consumer or CDN
/// can mistake the truncated bytes for a complete resource.
#[tokio::test]
async fn a_midstream_failure_aborts_the_body_so_it_is_never_cached_as_complete() {
    let root = hex64('a');
    let rk = hex64('b');
    let store = hex64('c');
    // The resource is incomplete (complete:false, more to come) but the second window errors.
    let replies = vec![
        window(b"FIRST", &root, false, Some(5), Some("cAo="), Some(&[10])),
        json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": -32603, "message": "boom" }}),
    ];
    let (node, _st) = spawn_stub(replies).await;

    let resp = content_get(&node, &store, &rk, &format!("?root={root}"), &[]).await;
    // The status is committed to 200 (the first window fetched fine); it cannot be rewritten.
    assert_eq!(resp.status(), StatusCode::OK);
    // But collecting the body MUST error — the stream aborts rather than ending cleanly.
    let collected = resp.into_body().collect().await;
    assert!(
        collected.is_err(),
        "a mid-stream fault on an incomplete resource must abort the body, not end it cleanly"
    );
}

/// The clean path: a genuinely COMPLETE multi-window resource streams a clean `200` whose body reads
/// to a full, error-free end — the anti-truncation guard must NOT fire on legitimate completion.
#[tokio::test]
async fn a_complete_multiwindow_resource_streams_a_clean_full_body() {
    let root = hex64('a');
    let rk = hex64('b');
    let store = hex64('c');
    let replies = vec![
        window(b"AAAA", &root, false, Some(4), Some("cAo="), Some(&[8])),
        window(b"BBBB", &root, true, None, None, None),
    ];
    let (node, _st) = spawn_stub(replies).await;

    let resp = content_get(&node, &store, &rk, &format!("?root={root}"), &[]).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let collected = resp
        .into_body()
        .collect()
        .await
        .expect("a complete resource streams without a body error");
    assert_eq!(collected.to_bytes().as_ref(), b"AAAABBBB");
}
