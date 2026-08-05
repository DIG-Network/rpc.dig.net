# SPEC — `rpc.dig.net`

Normative specification of the public DIG Network gateway. An independent implementation built
against this document MUST be substitutable for the one in this repository.

Layering: this document is the service's own contract. It agrees with `SYSTEM.md` (the ecosystem
interaction map) and the docs.dig.net protocol pages; where a shared contract changes, all three
change together.

Key words MUST / MUST NOT / SHOULD / MAY are to be read as in RFC 2119.

---

## 1. What this service is

`rpc.dig.net` is a **wrapper around a real DIG node**, not a node and not a reimplementation of
one.

Two processes run on one host:

| process | owns |
|---|---|
| **`dig-node`** | everything that makes a node a node: peer-RPC + DHT on `9444`, gossip on `9445`, the `.dig` capsule store, chain watch, peer selection, the local surface on `127.0.0.1:9778` |
| **the gateway** (this repo) | the anonymous public read tier: plain HTTPS + CORS for browsers, and nothing else |

The gateway MUST NOT implement content reads, proofs, manifests, peer exchange, the DHT, gossip,
or capsule storage. Every answer it returns for a content method MUST come from the node.

`rpc.dig.net` is the **final fallback** of the client→node ladder (`CLAUDE.md` §5.3:
`dig.local` → `localhost` → `rpc.dig.net`). An explicitly configured node always wins.

### 1.1 Names

| name | is | reachable |
|---|---|---|
| `rpc.dig.net` | the read tier | CloudFront → the gateway |
| `node-rpc.dig.net` | the node itself | `9444`, `9445` — directly, from any peer |

They are separate names on purpose: one is a CDN-fronted read surface, the other is a peer address
that goes in address books. Conflating them would put the read tier's edge in the peer dial path.

---

## 2. The boundary invariant

> **No write, peer, or control surface is reachable from the anonymous read tier.**

This is the service's single most important property. Everything in §3 and §4 exists to hold it.

The invariant is non-obvious because the node's own local surface on `9778` is designed for
loopback and is **not safe to expose**. Alongside public content reads it serves:

- wallet JSON-RPC on bare method names (`POST /:method`),
- a wallet WebSocket (`GET /ws`),
- `GET /s/*` — store content **already decrypted server-side**,
- `GET /verify/*`.

Therefore the gateway MUST NOT be a reverse proxy. It MUST be deny-by-default in two independent
dimensions, route and method, and a request MUST satisfy both.

---

## 3. Route surface (normative)

The gateway MUST expose exactly these routes and no others.

| method + path | behaviour |
|---|---|
| `POST /` | JSON-RPC 2.0. Screened per §4; forwarded to the node only if allowed. |
| `GET /` | Health, identical to `GET /health`. |
| `GET /health` | `{"status":"ok","service":"rpc.dig.net","version":"<semver>"}`. Answered by the gateway. |
| `GET /version` | `{"version":"<semver>"}`. Answered by the gateway. |
| `OPTIONS /` | CORS preflight. |

Requirements:

1. There MUST be no wildcard or path-prefix route, and no fallback that reaches the node. An
   unmatched path MUST be answered by the gateway with HTTP `404` and body
   `{"error":"not_found","message":"unknown route"}`.
2. `/health` and `/version` MUST be answered locally. A liveness probe MUST NOT be a path to the
   node.
3. The gateway MUST NOT forward any inbound request header that the node could read as
   authorization or as a client identity.
4. CORS MUST allow any origin for `GET`, `POST`, `OPTIONS`. The read tier is anonymous and
   browser-facing by design; there is no cookie, no credential, and therefore nothing for a
   permissive origin policy to leak.

---

## 3a. The path-addressed content read (normative)

CloudFront routes `GET /stores/{store_id}/content/{rk}` to the gateway so a browser (the hub's
service worker) can fetch immutable ciphertext by URL rather than by JSON-RPC. This is a
**read-only translation**, not a proxy and not a new tier: the gateway accepts exactly this one
path shape and issues only `dig.getContent` calls (paging the resource's windows). Writes and
§21.9-authenticated reads are
**NOT** on this surface — admitting either would violate the boundary invariant (§2, this document
line 46) and the header-stripping rule (§3.3). Only the anonymous content read lives here.

### 3a.1 Request

| element | requirement |
|---|---|
| `store_id` (path) | MUST be 64-hex (a 32-byte store id) |
| `rk` (path) | MUST be 64-hex (a 32-byte retrieval key) |
| `root` (query) | REQUIRED, MUST be 64-hex — the chain-anchored root the caller pins |
| `Range` header / `?range=` | OPTIONAL single explicit-start byte range (`bytes=start-end` or `bytes=start-`) |

A malformed or missing `store_id`, `rk`, or `root` MUST be answered `400` with
`Cache-Control: no-store`. An error MUST NEVER be returned with the immutable cache directive.

### 3a.2 Translation, streaming, and bounds

The gateway MUST issue `dig.getContent` to the node over loopback, following `next_offset` until the
requested span is covered, decoding the base64 `ciphertext` and capturing `inclusion_proof` +
`chunk_lens` from the offset-0 window. It MUST forward NO inbound `Authorization`, cookie, or
client-identity header on the loopback call (§3.3) — only the JSON-RPC body crosses.

The response body MUST be **streamed**, not assembled: the gateway fetches the first window (for the
headers, and so an upstream failure is detectable while the status is still mutable), then streams
each subsequent window's bytes as they arrive, holding only ~one window in memory at a time. It MUST
NOT buffer the whole resource. Because memory is bounded by streaming, the gateway MUST NOT impose a
resource-size cap and MUST NOT return `413` (or any size-dependent status) on the content path: a
size-dependent status is a **holdings oracle** — a held resource above a cap would answer differently
from a not-held key's small decoy, revealing that the key is held. Every content read is `200`.

The fetch MUST be **range-scoped**: for a `Range` request the gateway MUST stream only the windows
overlapping `[start, end]` (paging from the covering window of `start`, slicing the tail window to
`end`), never windows outside the span. The gateway MUST enforce a maximum window-iteration count and
MUST require strict forward progress (a non-advancing `next_offset` MUST terminate the stream) — an
anti-spin bound only; it MUST NOT change the committed `200` status.

**An abnormal termination of an INCOMPLETE resource MUST abort the body, never end it cleanly.** The
status is committed to `200` before the body streams and cannot be rewritten, but a clean chunked EOF
tells CloudFront the (immutable) response is COMPLETE — it would then cache a TRUNCATED ciphertext for
a year, permanently breaking that content URL (the reader's AEAD tag fails on the short bytes).
Therefore a mid-stream upstream failure, a non-advancing node, or the window-budget trip on a resource
that is not yet `complete` MUST terminate the body with a transfer ERROR (an aborted stream), so a CDN
or client treats the response as incomplete and REFUSES to cache it. The body MAY end cleanly ONLY on
genuine completion (the node's `complete`) or once a bounded range has been fully delivered.

### 3a.3 Response

A served read MUST return `200` with:

| header | value |
|---|---|
| body | the raw ciphertext bytes for the requested span (NOT JSON), streamed |
| `Content-Type` | `application/octet-stream` |
| `Content-Length` | the exact streamed byte count, when the offset-0 window was fetched (see below) |
| `Cache-Control` | `public, max-age=31536000, immutable` |
| `Access-Control-Allow-Origin` | `*` |
| `Access-Control-Expose-Headers` | `x-dig-inclusion-proof, x-dig-chunk-lens, x-dig-total-length` |
| `X-Dig-Total-Length` | full-resource CIPHERTEXT byte count = sum(`chunk_lens`), when the offset-0 window was fetched |
| `X-Dig-Inclusion-Proof` | the inclusion proof (base64), when present |
| `X-Dig-Chunk-Lens` | the per-chunk lengths, comma-joined decimals, ONLY for a multi-chunk resource |

`chunk_lens` are CIPHERTEXT byte lengths, so `sum(chunk_lens)` is the total ciphertext byte count
(the value carried by `X-Dig-Total-Length`). When the gateway fetched the offset-0 window it knows the
exact byte count it will stream, and it MUST set `Content-Length` accordingly — the whole-resource
total for a whole read, or the clamped range size for a range that starts at 0. This is a second,
independent defence against a truncated body being cached (a short body also fails the declared
length). A **mid-range** read (`start > 0`) never fetches offset 0, so it has no `chunk_lens`; the
gateway MUST omit `Content-Length` for that case only.

The gateway MUST NOT set `X-Dig-Root`, `ETag`, `Accept-Ranges`, or `Content-Range` — the URL is
already content-addressed and the immutable cache-control carries permanence. The
`Access-Control-Expose-Headers` list is REQUIRED: without it a cross-origin browser cannot read the
`X-Dig-*` headers.

**Range semantics are full-`200` slice, never `206`/`416`.** A `Range` request MUST return `200`
with the sliced bytes; a start at or beyond the resource end MUST return `200` with an empty body.
The gateway MUST NOT return `206`, `416`, `Content-Range`, or `Accept-Ranges`: a `206`-vs-`416`
distinction leaks whether the resource is large enough to satisfy the range, a key-existence oracle,
and a `416` carrying the immutable directive is additionally a cache-poisoning vector.

### 3a.4 The decoy rule (MUST)

A missing or unauthorized key — **including** an upstream `-32004` `RESOURCE_UNAVAILABLE` — MUST be
answered `200` with the node's constant-time decoy ciphertext, and **MUST NEVER** be answered `404`.
The node emits the decoy; the gateway relays it and MUST NOT synthesize its own. The gateway MUST
NOT introduce any status, length, header-set, or timing divergence between a real hit and a decoy —
any such divergence is a key-existence oracle. Accordingly the gateway reads the node's `result`
window whether or not a `-32004` error field accompanies it. A reply carrying no content window at
all (a transport failure or a bare error) MUST be `502` with `Cache-Control: no-store` — never
`404`.

---

## 4. The tier gate (normative)

A `POST /` body reaches the node only if **every** JSON-RPC call it contains names a method on the
public-read allowlist.

### 4.1 Allowlist

```
dig.getContent            dig.getManifest           dig.getAnchoredRoot
dig.getCapsule            dig.getMetadata           dig.getCollection
dig.getModule             dig.getPublicManifest     dig.listCollectionItems
dig.getProof              dig.listCapsules          dig.health
dig.getProofStatus                                  dig.methods
```

`dig.getModule` is the historical alias of `dig.getCapsule`. The chain-anchored reads
(`dig.getAnchoredRoot`, `dig.getCollection`, `dig.listCollectionItems`) are PUBLIC-READ per the
canonical tier ruling in `DESIGN_DIG_RPC.md` §2.5.

### 4.2 Matching

Matching MUST be exact: byte equality against the allowlist. Implementations MUST NOT case-fold,
trim, normalise, or prefix-match. A gateway that normalises can disagree with the node about which
method was invoked, and that disagreement is the bypass.

### 4.3 Deny by default

A method that is not on the allowlist MUST be denied. This includes methods the gateway has never
heard of. A node upgrade that introduces a method MUST NOT widen the public surface until the
method is added here explicitly.

### 4.4 Envelope rules

| condition | required response code |
|---|---|
| body is not valid JSON | `-32700` parse error |
| body is neither object nor array | `-32600` invalid request |
| empty batch `[]` | `-32600` |
| batch longer than `MAX_BATCH_CALLS` (32) | `-32600` |
| a batch member that is not an object | `-32600` |
| a call with no `method`, or `method` not a string | `-32600` |
| any call names a non-allowlisted method | `-32601` method not found |

The method-less case is load-bearing: the node's DHT (`find_node`, `find_providers`,
`add_provider`, `ping`) and PEX (`pex_handshake`, `pex_snapshot`, `pex_delta`) families are
dispatched on body *shape*, not on a `method` name. Refusing a method-less body is what prevents a
peer-transport frame from being posted to the read tier.

### 4.5 Batches are all-or-nothing

If any member of a batch is denied, the **whole batch** MUST be denied. An implementation MUST NOT
forward the permitted members. Partial execution would let a caller smuggle a restricted call
beside a legitimate one and learn from the reply shape that it was stripped.

### 4.6 Restricted methods answer `-32601`, not a forbidden code

A restricted method MUST return `-32601 method not found` — the same answer as a method that does
not exist. An anonymous caller MUST NOT be able to distinguish "exists but privileged" from
"unknown". This matches how the node answers management methods on its own peer surface
(dig-node `SPEC.md` §11).

### 4.7 Limits

| limit | value | why |
|---|---|---|
| request body | 256 KiB | a read request carries ids, roots and ranges; larger is a memory-pressure lever |
| batch calls | 32 | a batch is a request amplifier: one HTTP request, N capsule reads |
| upstream call | 25 s | |
| whole request | 30 s | backstop above the upstream timeout |

### 4.8 Error envelope

Errors MUST be returned with HTTP `200` and a JSON-RPC 2.0 error object:

```json
{ "jsonrpc": "2.0", "id": null,
  "error": { "code": <int>, "message": "<short>", "data": { "origin": "rpc.dig.net" } } }
```

Messages MUST be short and MUST NOT reveal upstream state, the node's address, or which internal
check refused the request.

---

## 5. The capsule store

The node's capsule cache is **backed by S3 and read-only to the node**.

### 5.1 Layout

```
<DIG_NODE_CACHE>/modules/{store_hex}/{root_hex}.dig    <- Mountpoint for S3, READ-ONLY
<DIG_NODE_CACHE>/downloads/                               <- local EBS
<DIG_NODE_CACHE>/responses/                               <- local EBS
<DIG_NODE_CACHE>/peer-net/                                <- local EBS
<DIG_NODE_CACHE>/.dignode.lock, config.json               <- local EBS
```

Only `modules/` is mounted. The cache **root** MUST be writable local disk.

### 5.2 Why the split is mandatory, not a preference

The cache tree is a mixed workload and only one subtree is object-storage compatible:

| path | operation | S3-mountable |
|---|---|---|
| `modules/` read | whole-file `std::fs::read`, no seek, no mmap | yes |
| `downloads/*.download.tmp` | `O_RDWR` + `seek` + **arbitrary-order** `write_at` | **no** |
| `downloads/state/*.json` | rewritten per completed range | no |
| `responses/*.json` | overwrite | no |
| `peer-net/identity/` | `chmod 0700/0600` + rename | no |
| `.dignode.lock` | `O_RDWR` held open, `flock` | no (degrades) |

An implementation MUST NOT mount the cache root. dig-node write-probes the root on **every** cache
path resolution and, if the probe fails, **silently relocates the entire cache to the system temp
directory** rather than erroring — a root-mounted deployment would appear healthy while serving
from ephemeral local disk.

### 5.3 Read-only is a security property

The mount MUST be read-only. This is what makes "no maximum cache capacity" safe: the node
physically cannot grow its own capsule store, so no anonymous request can cause unbounded storage
growth. The cache is bounded by S3 and writable only by the publish path.

Cache-on-fetch (`sync_module_from`) will fail against the read-only mount. That is expected and
MUST be tolerated: dig-node returns `false` and continues serving. It MUST NOT be treated as an
error condition.

### 5.4 Capacity

`DIG_NODE_CACHE_CAP` MUST be set to `18446744073709551615` (`u64::MAX`), which makes eviction a
no-op. `0` MUST NOT be used — it falls through to the 1 GiB default.

The cap governs only the response cache in any case; capsules are durable inventory and are never
LRU-evicted (dig-node `SPEC.md` §6).

### 5.5 The publish contract

The hub's publish path is the **only** writer. It MUST write one object per published capsule:

```
s3://<capsule bucket>/{store_hex}/{root_hex}.dig
```

- `store_hex` and `root_hex` are lowercase hex, no `0x`.
- The suffix MUST be `.dig` — the canonical capsule artifact extension ecosystem-wide, and the same
  suffix dig-node's `module_path` writes. The hub's own bucket uses `.dig` too; these remain separate
  objects in separate buckets with separate lifecycles, but they no longer differ in shape.
- A reader MAY tolerate a legacy `.module` object written by an older binary, but a writer MUST NOT
  create one. The live bucket was migrated to `.dig` on 2026-08-02 and holds no `.module` objects.
- Objects are content-addressed and immutable. A writer MUST NOT overwrite an existing key with
  different bytes.

---

## 6. Ports

| port | protocol | exposure | owner |
|---|---|---|---|
| `9444` | TCP, mTLS | internet, dual-stack | dig-node — peer-RPC + DHT |
| `9445` | TCP | internet, dual-stack | dig-node — gossip |
| `3478` | UDP | **off by default** | STUN, only if the node serves it |
| gateway (`443`) | TCP | **CloudFront origin ranges only** | the gateway |
| `9778` | TCP | **loopback only — never exposed** | dig-node local surface |

`9778` MUST NOT appear in any security group. STUN defaults off: an open UDP reflector is a
reflection/amplification surface, and being a peer does not require being a STUN server.

IPv6 is preferred and IPv4 is the fallback, per `CLAUDE.md` §5.2. Both A and AAAA records MUST
exist for the peer host.

---

## 7. Configuration

| variable | default | meaning |
|---|---|---|
| `GATEWAY_LISTEN` | `0.0.0.0:8080` | gateway bind address |
| `DIG_NODE_URL` | `http://127.0.0.1:9778` | the wrapped node; MUST be loopback |
| `GATEWAY_TLS_CERT` | — | PEM certificate chain served on the origin hop |
| `GATEWAY_TLS_KEY` | — | PEM private key for that chain |
| `RUST_LOG` | `info` | log filter |

`DIG_NODE_URL` MUST point at loopback. Pointing it at a remote node would send unauthenticated
read traffic across a network the gateway does not control.

### 7.1 Origin TLS

The origin hop MUST be TLS. Not for the payload's sake — capsule bytes are already ciphertext with
merkle proofs — but because the request path names the capsule being read, and in the clear that
discloses to any on-path observer which capsule each READER is fetching.

When `GATEWAY_TLS_CERT`/`GATEWAY_TLS_KEY` name a keypair the gateway cannot read and parse, the
gateway MUST exit non-zero at startup. **There is no plaintext fallback mode**, and no deployment
may describe one: an operator told the service is running without TLS will look in the wrong place,
which is exactly how dig_ecosystem#2037 stayed misdiagnosed while the read tier was down.

A deployment MUST be able to replace the host that serves this certificate without obtaining a new
one. Certificate authorities rate-limit issuance, so a deployment that re-issues per replacement
makes routine redeployment consume a scarce external resource and can lock itself out of its own
origin.

### 7.2 The node version, and what pins it

The wrapped `dig-node` MUST track the newest **stable** `dig-node` release without human action.
A deployment where advancing the node requires someone to remember MUST be treated as defective:
this one sat nine minor versions behind for want of a manual step, including past the fix for a
live outage.

**`DIG_NODE_VERSION` is the bootstrap floor and the record of what is installed — not a manual
pin.** It states which release a *fresh* instance installs at boot, and it is maintained
automatically: whatever moves the running node MUST move it in the same operation. Two rules
follow, and both are load-bearing:

- The recorded version and the running version MUST NOT be allowed to diverge. If they may
  diverge, the node's version becomes a function of whether an update or a deploy happened most
  recently — a redeploy silently reverts the node, which is the same "nobody chose this version"
  outcome a manual pin exists to prevent, reached from the other side.
- A pinned version MUST remain expressible for a deliberate rollback, and choosing one MUST also
  stop automatic selection from immediately undoing it.

An update MUST:

1. Install only a **published stable release** — never a prerelease, a draft, or a nightly — and
   only its raw executable for the host's architecture. A packaged artifact (`.deb`, `.pkg`,
   `.msi`) MUST NOT be installed as the node binary.
2. Verify the artifact's SHA-256 **before** installing it, against a digest computed from the
   bytes that will be installed. A digest read from a checksum file or an API response does not
   satisfy this: the host is internet-facing on two peer ports, and an unverified download is not
   an acceptable install path.
3. Confirm the artifact **executes on the host** before it replaces the running binary. A checksum
   establishes provenance, not that the file can be loaded on this architecture.
4. Leave the node **running** on any failure. A failed update MUST NOT leave a half-installed
   binary or a stopped service, and MUST restore the previous binary if the new one does not
   serve.
5. Judge success on **what is served**, not on what was installed: the node answering as the
   installed version, through the gateway. An update that leaves the read tier down MUST fail.
6. Move the node forward only. A downgrade MUST require an explicit request naming the version.

Nothing about this may introduce a second writer of the deployment (§7.1's certificate reasoning
applies to the whole stack): exactly one mechanism applies infrastructure, and an update path that
changes what runs on the host MUST be mutually exclusive with it.

---

## 8. Observability

- `GET /health` returns liveness and the running semver.
- A refused method name is caller-controlled input and MUST NOT be written to the default log
  stream at info or above.
- No secret, key, cert, or client identity is ever logged.

---

## 9. Conformance

An implementation conforms when:

1. Every method in §4.1 is forwarded and answered by the node.
2. Every method absent from §4.1 returns `-32601`, including unknown methods.
3. A batch containing one restricted method is refused in full.
4. A method-less body is refused.
5. No route other than those in §3 exists, and none of them but `POST /` contacts the node.
6. `9778` is not reachable from any address other than loopback.
7. A capsule published to the bucket is served without the file existing on the instance's disk.
8. A new stable `dig-node` release reaches the running node with no human action (§7.2).
9. An update offered a mismatched checksum, a packaged artifact, or a build that cannot execute on
   the host installs nothing and leaves the node serving.
10. A release that installs but does not serve is rolled back, and the deployment's recorded
    version still names the release that is actually running.
11. `GET /stores/{store_id}/content/{rk}?root=…` (§3a) STREAMS the node's ciphertext as raw bytes
    with the pinned header set (`Content-Type`, `Content-Length` = sum(`chunk_lens`) when the offset-0
    window was fetched, immutable `Cache-Control`, `Access-Control-Allow-Origin: *`,
    `Access-Control-Expose-Headers`, `X-Dig-Total-Length`, `X-Dig-Inclusion-Proof`, and
    `X-Dig-Chunk-Lens` for a multi-chunk resource) and NO `X-Dig-Root`, `ETag`, `Accept-Ranges`, or
    `Content-Range` (`Content-Length` is omitted only for a mid-range `start > 0` read); a malformed
    address is `400 no-store`; EVERY served read is `200` — including a whole read larger than any
    former cap and a missing/unauthorized key (incl. upstream `-32004`), which streams a `200` decoy,
    never `404` and never a size-dependent `413`, with no status/length/header-set divergence from a
    real hit; a byte range returns `200` with the sliced bytes (never `206`/`416`) and streams only the
    overlapping windows; an abnormal termination of an incomplete resource ABORTS the body (transfer
    error) so a truncated ciphertext is never cached as complete, while a genuinely complete resource
    ends cleanly; an upstream failure with no window is `502 no-store`; memory is bounded to ~one window
    by streaming (no size cap); and no inbound auth header reaches the node.
