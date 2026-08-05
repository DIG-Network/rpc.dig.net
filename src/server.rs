//! The HTTP surface: routes, CORS, limits, and the loopback forward.
//!
//! This lives in the library rather than in `main` so the boundary can be driven by tests. The
//! interesting properties are not "does the gate function return the right enum" — [`crate::gate`]
//! covers that — but "does an unmatched path reach the node", "is `/health` really answered
//! locally", "does a denied method produce a reply without any upstream call at all". Those are
//! properties of the wiring, and the wiring is only testable if it is a value you can construct.

use std::collections::HashMap;
use std::time::Duration;

use axum::{
    body::{Body, Bytes},
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::Engine as _;
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
/// Two routes reach the node, both read-only and both narrowly shaped:
/// - `POST /` — JSON-RPC, forwarded only after [`screen`] allows every call in the body.
/// - `GET /stores/:store_id/content/:rk` — the path-addressed anonymous content read
///   ([`content_get`]). It is NOT a proxy: it accepts only this one fixed shape, translates it into
///   a single hardcoded `dig.getContent` call, and returns raw ciphertext. It carries no auth and
///   exposes no write or §21.9-authenticated path — those stay off the read tier by design.
///
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
        .route("/stores/:store_id/content/:rk", get(content_get))
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

// -- The path-addressed content read (#2000) ------------------------------------------------------
//
// CloudFront routes `GET /stores/{id}/content/{rk}` here so the hub's service worker can fetch
// immutable ciphertext by URL. This is a READ-ONLY translation, not a proxy: it accepts exactly one
// path shape, validates it, and emits a single hardcoded `dig.getContent` JSON-RPC call over the
// loopback. It never forwards an inbound header (§3.3), never reaches a write or authenticated-read
// method, and — critically — never turns a missing/unauthorized key into a distinguishable answer:
// the node serves a constant-time decoy for such keys, and this handler relays that decoy as a plain
// `200`, byte-for-byte the same shape as a real hit (see [`content_get`]'s decoy handling).
//
// The body is STREAMED, not assembled: the handler fetches the node's first `dig.getContent` window
// (for the headers + to detect an upstream failure while the status is still mutable), then streams
// the remaining windows straight through, holding only ~one window in memory at a time. That is what
// makes the endpoint safe on a public, fixed-memory host WITHOUT a size cap — and dropping the cap is
// deliberate: a `413` on an over-size read was a HOLDINGS ORACLE (a held resource > cap returned
// `413` while a not-held key returned the node's small decoy as `200`, so `413` proved holding).
// EVERY content read is now `200` (an out-of-range start streams an empty `200` body); the only
// non-200 statuses are `400` (malformed input) and `502` (upstream failure), both `no-store`.
//
// An ABNORMAL termination of an incomplete resource (a mid-stream upstream fault, a non-advancing
// node, or the window-budget trip) aborts the body with an error rather than ending it cleanly — a
// clean chunked EOF would tell CloudFront the immutable response is complete and cache a TRUNCATED
// ciphertext for a year (see `content_stream`).
//
// The envelope is pinned to the retired dighub-retrieval Lambda + what the hub service worker reads:
// the header set `{content-type, content-length (when the offset-0 window is fetched), cache-control
// immutable, access-control-allow-origin *, access-control-expose-headers, x-dig-total-length,
// x-dig-inclusion-proof, x-dig-chunk-lens (multi-chunk only)}` — `content-length` = sum(chunk_lens),
// the total CIPHERTEXT byte count (the same value as `x-dig-total-length`), and is a second defence
// against a truncated body being cached; deliberately NO `x-dig-root`, NO `ETag`, and NO `206`/`416`/
// `Content-Range`/`Accept-Ranges` — the URL is content-addressed and the immutable cache-control
// carries permanence.

/// 1-year immutable caching. A `{store, root, rk}` triple names content-addressed bytes that can
/// never change under that address, so the strongest cache directive is correct — and it MUST be
/// identical on a decoy so cache behaviour cannot become a key-existence oracle.
const IMMUTABLE_CACHE: &str = "public, max-age=31536000, immutable";

/// The `X-Dig-*` response headers a cross-origin browser (the hub service worker) must be allowed to
/// READ. `access-control-allow-origin: *` alone is not enough — without an explicit expose list a SW
/// literally cannot read these off the response. Set on the content read to match the retired
/// dighub-retrieval Lambda; the CORS layer supplies the matching `access-control-allow-origin: *`.
const EXPOSE_HEADERS: &str = "x-dig-inclusion-proof, x-dig-chunk-lens, x-dig-total-length";

/// Hard cap on `dig.getContent` windows streamed for one request, so a malicious or buggy node that
/// answers `complete:false` forever (or advances `next_offset` by a trickle) cannot spin the paging
/// stream unboundedly. This is an anti-SPIN bound, not a memory bound: memory is already bounded to
/// ~one window by streaming, so this exists only to terminate a non-terminating node, and hitting it
/// simply ends the (already-`200`) body — it never changes the status, so it is not a holdings oracle.
const MAX_WINDOWS: usize = 100_000;

/// `GET /stores/:store_id/content/:rk` — the anonymous, path-addressed content read.
///
/// Translates the URL into a `dig.getContent` fetch against the loopback node and returns the raw
/// ciphertext with the proof/layout carried in `X-Dig-*` headers. `root` is a REQUIRED query
/// parameter: the caller pins the chain-anchored root it expects so a compromised node cannot
/// substitute a different generation.
///
/// Range semantics are FULL-200 SLICE, matching the retired dighub-retrieval Lambda: a `Range`
/// header or `?range=` returns `200` with the sliced bytes (an out-of-range start yields an empty
/// body, still `200`). There is deliberately no `206`/`416` — that split leaks whether a resource is
/// large enough for the range to be satisfiable, a key-existence oracle. The fetch is range-scoped:
/// only the windows overlapping the requested span are STREAMED, never the whole resource.
///
/// Status discipline (the boundary this handler must not break):
/// - `400` (never cached) for a malformed `store_id`/`rk`/`root`.
/// - `200` for EVERY served read — a real hit AND a decoy are indistinguishable, and there is no
///   size-dependent status (no `413`) that could reveal that a key is held-and-large.
/// - `502` (never cached) for a transport failure or an upstream reply that carries no window.
/// - never `404`: a missing/unauthorized key is answered by the node's decoy, relayed as `200`.
async fn content_get(
    State(gw): State<Gateway>,
    Path((store_id, rk)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    // -- Validate the address. All three are 32-byte hashes rendered as 64-hex. --
    let Some(root) = params.get("root").cloned() else {
        return bad_request("root query parameter is required");
    };
    if !is_hex64(&store_id) || !is_hex64(&rk) || !is_hex64(&root) {
        return bad_request("store_id, rk and root must each be 64-hex");
    }

    // -- Resolve the requested span. A parseable range scopes the fetch; anything else is whole. --
    let range = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| params.get("range").cloned())
        .and_then(|s| parse_byte_range(&s));
    let start = range.map_or(0, |(s, _)| s);
    let end_incl = range.and_then(|(_, e)| e);

    // -- Fetch the FIRST window eagerly: the headers come from it, and an upstream failure must be
    //    detectable while the status is still mutable (once the `200` body streams, it is too late). --
    let first = match fetch_window(&gw, &store_id, &root, &rk, start as u64).await {
        Ok(w) => w,
        Err(()) => return upstream_error(),
    };

    // -- Emit the pinned envelope BEFORE the body (identical for a real hit and a decoy). --
    let mut resp_headers = HeaderMap::new();
    insert_static(&mut resp_headers, header::CACHE_CONTROL, IMMUTABLE_CACHE);
    insert_static(
        &mut resp_headers,
        header::CONTENT_TYPE,
        "application/octet-stream",
    );
    insert_static(
        &mut resp_headers,
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        EXPOSE_HEADERS,
    );
    if let Some(proof) = &first.inclusion_proof {
        insert_value(&mut resp_headers, "x-dig-inclusion-proof", proof);
    }
    if let Some(lens) = &first.chunk_lens {
        // `chunk_lens` are CIPHERTEXT byte lengths, so their sum is the total ciphertext byte count
        // of the whole resource (= the retired Lambda's `total_len`). `x-dig-total-length` carries it
        // (read from the first window, without assembling anything); `x-dig-chunk-lens` is emitted
        // ONLY for a multi-chunk resource (a single-chunk layout carries no useful per-chunk split).
        let total: u64 = lens.iter().map(|&n| u64::from(n)).sum();
        insert_value(&mut resp_headers, "x-dig-total-length", &total.to_string());

        // Content-Length is a second, independent defence against a truncated body being cached: we
        // only reach here having fetched offset 0, so we know the exact byte count we will stream — a
        // whole read is `total`, a range that starts at 0 is the clamped range size. A mid-range
        // (start > 0) never fetches offset 0, so it has no `chunk_lens` and its length is omitted.
        let content_length = match end_incl {
            Some(end) => (end as u64)
                .saturating_add(1)
                .min(total)
                .saturating_sub(start as u64),
            None => total.saturating_sub(start as u64),
        };
        insert_value(
            &mut resp_headers,
            header::CONTENT_LENGTH,
            &content_length.to_string(),
        );

        if lens.len() > 1 {
            let csv = lens
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",");
            insert_value(&mut resp_headers, "x-dig-chunk-lens", &csv);
        }
    }

    let body = content_stream(gw, store_id, root, rk, start, end_incl, first);
    (StatusCode::OK, resp_headers, body).into_response()
}

/// One `dig.getContent` window: the decoded ciphertext plus the paging + first-window metadata.
struct Window {
    /// The decoded ciphertext bytes of this window.
    bytes: Vec<u8>,
    /// The inclusion proof (base64) — only ever populated for the offset-0 window.
    inclusion_proof: Option<String>,
    /// The full-resource per-chunk lengths — only ever populated for the offset-0 window.
    chunk_lens: Option<Vec<u32>>,
    /// Whether this is the last window of the resource.
    complete: bool,
    /// The next offset to request, when not `complete`.
    next_offset: Option<u64>,
}

/// Fetch a single `dig.getContent` window at `offset` for `(store, root, rk)`.
///
/// The decoy invariant lives here: the node answers a missing/unauthorized key — and a `-32004`
/// `RESOURCE_UNAVAILABLE` — with a constant-time decoy carried as a normal `result` window. This
/// reads `result` and ignores any co-resident `error` field, so a decoy window is fetched exactly
/// like a real one. A reply with NO window at all (a transport failure, non-JSON, non-base64, or a
/// missing `result`) is an [`Err`], which the caller renders as `502` on the FIRST window and simply
/// ends the stream on a later one — never a `404`.
async fn fetch_window(
    gw: &Gateway,
    store_id: &str,
    root: &str,
    rk: &str,
    offset: u64,
) -> Result<Window, ()> {
    // Only the JSON-RPC body crosses the loopback — no inbound auth/identity/cookie header is ever
    // forwarded (§3.3). `gw.http` is a fresh client that adds none of its own.
    let req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "dig.getContent",
        "params": { "store_id": store_id, "root": root, "retrieval_key": rk, "offset": offset }
    });
    let resp = match gw.http.post(&gw.node_url).json(&req).send().await {
        Ok(r) => match r.json::<Value>().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "node content reply was not JSON");
                return Err(());
            }
        },
        Err(e) => {
            tracing::warn!(error = %e, "node unreachable for content read");
            return Err(());
        }
    };

    let Some(result) = resp.get("result") else {
        tracing::warn!("node content reply carried no window");
        return Err(());
    };

    let window_b64 = result
        .get("ciphertext")
        .and_then(Value::as_str)
        .unwrap_or("");
    let bytes = match base64::engine::general_purpose::STANDARD.decode(window_b64) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "node returned non-base64 ciphertext");
            return Err(());
        }
    };

    // Proof + layout ride only the offset-0 window.
    let (inclusion_proof, chunk_lens) = if offset == 0 {
        let proof = result
            .get("inclusion_proof")
            .and_then(Value::as_str)
            .map(str::to_string);
        let lens = result
            .get("chunk_lens")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_u64)
                    .map(|n| n as u32)
                    .collect::<Vec<_>>()
            });
        (proof, lens)
    } else {
        (None, None)
    };

    Ok(Window {
        bytes,
        inclusion_proof,
        chunk_lens,
        complete: result
            .get("complete")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        next_offset: result.get("next_offset").and_then(Value::as_u64),
    })
}

/// Build the streaming response body: yield the (already-fetched) first window, then page the node
/// window-by-window until the requested span is covered or the resource is `complete`.
///
/// RANGE-SCOPED + BOUNDED-MEMORY: because it streams, only ~one window is ever held in memory — for
/// both a range and a whole read — so there is no need for a size cap (and thus no size-dependent
/// status that could leak holdings). A range yields at most `end - start + 1` bytes, slicing the tail
/// window exactly.
///
/// CLEAN-EOF ONLY ON GENUINE COMPLETION (anti cache-poisoning): the status is already committed to
/// `200`, so it cannot be rewritten — but ending the body with a clean chunked EOF tells CloudFront
/// the (immutable) response is COMPLETE, and it would cache a TRUNCATED ciphertext for a year,
/// permanently breaking that content URL (the SW's GCM-SIV tag would fail on the short bytes).
/// Therefore an ABNORMAL termination of an INCOMPLETE resource — a mid-stream upstream fault, a
/// non-advancing `next_offset`, or the `MAX_WINDOWS` trip — MUST `yield Err`, which aborts the body so
/// CloudFront and clients treat it as a transfer error and REFUSE to cache it. A clean `break` is
/// correct ONLY on genuine completion (`win.complete`) or once a bounded range has been fully
/// delivered (`remaining == 0`). Content-Length (set in [`content_get`] when offset 0 was fetched) is
/// the second, independent defence: a truncated body also fails the declared length.
fn content_stream(
    gw: Gateway,
    store_id: String,
    root: String,
    rk: String,
    start: usize,
    end_incl: Option<usize>,
    first: Window,
) -> Body {
    let stream = async_stream::stream! {
        // Bytes still allowed for a bounded range; `None` = stream to `complete`.
        let mut remaining: Option<usize> = end_incl.map(|e| e.saturating_sub(start).saturating_add(1));
        let mut win = first;
        let mut offset = start as u64;
        let mut windows_used = 1usize;

        loop {
            let mut bytes = win.bytes;
            if let Some(rem) = remaining {
                bytes.truncate(rem);
                remaining = Some(rem - bytes.len());
            }
            if !bytes.is_empty() {
                yield Ok::<Bytes, std::io::Error>(Bytes::from(bytes));
            }

            // Clean completion: the range was fully delivered, or the resource is done.
            if remaining == Some(0) || win.complete {
                break;
            }
            // Past here the resource is INCOMPLETE and the request unsatisfied — every stop is
            // abnormal and MUST abort the body, never a clean EOF that could be cached as complete.
            let next = match win.next_offset {
                // Strict forward progress; a non-advancing next_offset is a looping/hostile node.
                Some(n) if n > offset => n,
                _ => {
                    yield Err(std::io::Error::other(
                        "node stopped advancing before the resource completed",
                    ));
                    break;
                }
            };
            if windows_used >= MAX_WINDOWS {
                yield Err(std::io::Error::other(
                    "content read exceeded the window budget before completing",
                ));
                break;
            }
            offset = next;
            windows_used += 1;
            win = match fetch_window(&gw, &store_id, &root, &rk, offset).await {
                Ok(w) => w,
                // A later-window fault on an incomplete resource: abort so a truncated, immutable
                // body is never cached as complete.
                Err(()) => {
                    yield Err(std::io::Error::other("upstream failed mid-stream"));
                    break;
                }
            };
        }
    };
    Body::from_stream(stream)
}

/// A 64-character lowercase-or-uppercase hex string (a 32-byte hash). Nothing else is a valid
/// store id, retrieval key, or root on this route.
fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Parse a single `bytes=start-end` range into `(start, end_inclusive)` byte indices, or `None` when
/// the caller did not send a usable explicit-start range (in which case the whole resource is served,
/// still `200`). Only the first range of a comma list is honoured; an open end (`bytes=start-`) maps
/// to `(start, None)`. A suffix range (`bytes=-N`) needs the total length, which range-scoped fetch
/// deliberately does not resolve up front, so it is treated as "no range" — the service worker only
/// ever issues explicit-start aligned tiles.
fn parse_byte_range(spec: &str) -> Option<(usize, Option<usize>)> {
    let raw = spec.trim().strip_prefix("bytes=").unwrap_or(spec.trim());
    let first = raw.split(',').next()?.trim();
    let (start_s, end_s) = first.split_once('-')?;
    if start_s.is_empty() {
        return None; // suffix range — unsupported, fall back to a whole read
    }
    let start: usize = start_s.parse().ok()?;
    let end = if end_s.is_empty() {
        None
    } else {
        let e: usize = end_s.parse().ok()?;
        if e < start {
            return None;
        }
        Some(e)
    };
    Some((start, end))
}

/// A `400` JSON error that MUST NOT be cached — an error must never be frozen into the 1-year
/// immutable behaviour that a valid read carries.
fn bad_request(message: &str) -> Response {
    let mut resp = (
        StatusCode::BAD_REQUEST,
        Json(json!({ "error": "bad_request", "message": message })),
    )
        .into_response();
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// A `502` for a transport failure or an upstream reply with no content window. Never cached, and
/// deliberately NOT a `404`: a genuine missing key is answered by the node's decoy, not by this path.
fn upstream_error() -> Response {
    let mut resp = (
        StatusCode::BAD_GATEWAY,
        Json(json!({ "error": "upstream_error", "message": "content unavailable" })),
    )
        .into_response();
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// Insert a static header value, dropping it silently if it is somehow not a valid header value
/// (it never is for our constants) rather than failing the whole response.
fn insert_static(headers: &mut HeaderMap, name: header::HeaderName, value: &'static str) {
    headers.insert(name, HeaderValue::from_static(value));
}

/// Insert a runtime string header value, skipping it if the value cannot be encoded as a header
/// (a base64/hex/decimal string always can — this only guards against a hostile upstream).
fn insert_value<K>(headers: &mut HeaderMap, name: K, value: &str)
where
    K: axum::http::header::IntoHeaderName,
{
    if let Ok(v) = HeaderValue::from_str(value) {
        headers.insert(name, v);
    }
}
