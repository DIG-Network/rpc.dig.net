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
| `node.dig.net` | the node itself | `9444`, `9445` — directly, from any peer |

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
<DIG_NODE_CACHE>/modules/{store_hex}/{root_hex}.module    <- Mountpoint for S3, READ-ONLY
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
s3://<capsule bucket>/{store_hex}/{root_hex}.module
```

- `store_hex` and `root_hex` are lowercase hex, no `0x`.
- The suffix MUST be `.module`, matching dig-node's `module_path`. The hub's own bucket uses
  `.dig`; these are separate objects in separate buckets with separate lifecycles.
- Objects are content-addressed and immutable. A writer MUST NOT overwrite an existing key with
  different bytes.

---

## 6. Ports

| port | protocol | exposure | owner |
|---|---|---|---|
| `9444` | TCP, mTLS | internet, dual-stack | dig-node — peer-RPC + DHT |
| `9445` | TCP | internet, dual-stack | dig-node — gossip |
| `3478` | UDP | **off by default** | STUN, only if the node serves it |
| gateway (`8080`) | TCP | **CloudFront origin ranges only** | the gateway |
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
| `RUST_LOG` | `info` | log filter |

`DIG_NODE_URL` MUST point at loopback. Pointing it at a remote node would send unauthenticated
read traffic across a network the gateway does not control.

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
