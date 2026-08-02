# DEVELOPMENT_LOG — rpc.dig.net

Durable realizations. Context, not a change diary.

---

## The node's `9778` is not a read surface you can proxy

It is easy to assume the node's local port is "the read API" and put a reverse proxy in front of
it. It is not. Its router (`dig-node-service/src/server.rs:152-184`) serves, alongside content
reads:

- `POST /:method` — **wallet JSON-RPC on bare method names**
- `GET /ws` — a wallet WebSocket
- `GET /s/*path` — store content **already decrypted server-side**
- `GET /verify/*path`

That is why this gateway is an allowlist and not a proxy, and why the route table has no wildcard
and no fallback that reaches the node. Any change that adds a pass-through arm re-opens all four.

## The `.dig` cache is a mixed workload — only `modules/` can live on S3

The instinct is to mount `DIG_NODE_CACHE` on S3 and be done. That breaks, and worse, it breaks
*quietly*.

- `modules/` reads are whole-file `std::fs::read` with no seek and no mmap
  (`dig-node-core/src/lib.rs:1004`). Ranged serves slice an in-memory decoded copy
  (`lib.rs:1840`) behind a 256 MiB LRU (`lib.rs:1055-1078`), so a window read costs no disk I/O at
  all. Perfect for object storage.
- `downloads/` uses `O_RDWR` + `seek` + **arbitrary-order** `write_at`
  (`dig-download/src/sink.rs:154-176`; the trait doc says explicitly "in arbitrary range order").
  No S3 mount supports that.
- `peer-net/identity/` does `chmod 0700/0600` + rename. `.dignode.lock` holds an `O_RDWR` fd.

**The trap:** dig-node write-probes the cache **root** on *every* path resolution
(`dir_is_writable`, `lib.rs:416-430`, called from `resolve_cache_dir`, `lib.rs:438-455`). If the
probe fails it does not error — it silently relocates the whole cache to the system temp directory
and logs a warning. A root-mounted deployment looks healthy while serving from ephemeral disk.

So: mount `modules/` only, keep the root on local disk.

## Read-only on that mount is a security control, not a limitation

The ticket asked for an unbounded cache and also warned that an unbounded cache is a
disk-exhaustion surface. Both are satisfied by the same decision: make the mount read-only. The
node then *cannot* grow its own capsule store, so no anonymous request can cause storage growth,
and `DIG_NODE_CACHE_CAP` never has to be trusted.

Cache-on-fetch fails against it, and that is fine — `write_atomic` returns `Err` and
`sync_module_from` returns `false` without panicking (`lib.rs:1244-1246`). Verified before relying
on it.

## `DIG_NODE_CACHE_CAP=0` does not mean unbounded

`cache_cap_bytes` (`lib.rs:598-612`) guards on `cap > 0`, so `0` falls through to the 1 GiB
default. Unbounded is `18446744073709551615` (`u64::MAX`), which makes `plan_eviction`'s
`total <= cap` short-circuit always true.

Separately: the cap only ever governs the **response** cache. `evict_if_needed` is called from
exactly one site, with `responses_dir` (`lib.rs:1133`). Capsules are durable inventory and are
never LRU-evicted.

## The peer identity must outlive the instance

`peer_id = SHA-256(SPKI DER)` of a keypair under `<cache>/peer-net/identity`. On the root volume it
would be regenerated on every deploy, and the node would arrive as a stranger each time, falling
out of every address book that had cached it. Hence the separate EBS state volume with
`prevent_destroy`.

## A dead upstream makes the boundary tests falsifiable

`tests/boundary.rs` points the gateway at `127.0.0.1:1`. A denied call returns `-32601` (never
touched the network); an allowed call returns `-32603` (tried to forward, failed to connect). The
two codes distinguish "short-circuited" from "forwarded", so `an_allowed_method_is_forwarded_to_the_node`
is what stops every other test in the file from passing vacuously. Without it, a gateway that
denied *everything* would look fully correct.
