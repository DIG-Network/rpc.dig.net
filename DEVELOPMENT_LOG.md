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

## An instance replacement can consume a rate-limited external resource

`user_data_replace_on_change = true` plus a binary SHA in `user_data` means every release replaces
the EC2 instance. That was a deliberate, well-documented choice, and the cost was understood to be
"a few minutes of downtime". It was not. The origin certificate was obtained by `certbot certonly`
*in user_data*, so a replacement did not reuse a certificate — it **bought** one. Six replacements
in a day exhausted Let's Encrypt's five-per-week limit for the exact identifier set, and because
the gateway reads its certificate at startup and exits without one, the read tier was hard down for
~21 hours (dig_ecosystem#2037).

The generalisable lesson is not "cache the certificate". It is that **immutable-infrastructure
redeployment silently changes cost when anything in the boot path talks to a rate-limited external
service.** Before making a resource replace-on-change, enumerate what its boot path *acquires* —
certificates, registrations, licences, API-key provisioning, an identity the network has to learn —
and make each of those durable. The peer-identity EBS volume in this stack is the same lesson,
already learned once for `peer_id`; the certificate was the second instance of it and was missed.

Two smaller things worth keeping:

- **Let's Encrypt's duplicate-certificate limit is keyed on the EXACT identifier set.** Adding a
  second name to the request creates a distinct set with its own budget, and dns-01 means the extra
  name needs no A record — only that the zone exists. That is the emergency escape hatch when a set
  is exhausted, and it buys five more, so it is only viable together with making issuance rare.
- **Persist certbot's whole state directory, not the two PEM files.** Restoring only
  `fullchain.pem` and `privkey.pem` serves traffic today and then silently stops renewing, because
  certbot needs its `renewal/` config, its `archive/`, and its ACME account. That failure surfaces
  ~60 days later, nowhere near its cause.

## user_data is capped at 16 KiB, and the error is unreadable

Embedding a well-commented helper script pushed the rendered bootstrap to ~24 KiB and the apply was
rejected with `expected length of user_data to be in the range (0 - 16384), got` followed by the
entire script. The fix is `base64gzip` into `user_data_base64` — cloud-init sniffs the gzip magic
bytes and decompresses before running — which took ~24 KiB to ~8.9 KiB.

The limit therefore applies to the *compressed* bytes, which is a lot of headroom, but it is
invisible until an apply. The guard belongs at PR time, not deploy time: a test gzips the rendered
template and asserts the size, so the failure is a review comment instead of a red deploy.

## `set -e` kills a script at an assignment whose command substitution fails

`.github/update-node.sh` read the origin hostname out of `/etc/dig-origin-cert.env`:

```bash
ORIGIN_HOST="$(sed -n 's/^DIG_ORIGIN_CERT_HOST=//p' "$CERT_ENV" 2>/dev/null | head -1)"
ORIGIN_HOST="${ORIGIN_HOST:-node-rpc.dig.net}"     # the "fallback"
```

On a host without that file it exited **2, before printing anything at all** — looking exactly like
a bash syntax error, with the fallback never reached. Under `set -e` the exit status of a simple
assignment IS the status of its command substitution, so the shell exits there. The fallback only
gets to be a fallback if reading is allowed to fail: `… | head -1 || true`.

The neighbouring `A && B` idiom is NOT affected and does not need guarding — bash exempts a command
that fails as the non-final member of an `&&`/`||` list, which is why
`[ "$PING" = Online ] && break` has always been safe here. The two look alike and behave oppositely.

Worth keeping because of how it was found: the behavioural harness caught it on its first run. A
`bash -n` syntax check passes, `shellcheck` says nothing, and on the real host the file exists so
the bug is invisible — it would have surfaced only on a host where something else was already wrong.

## rpc.dig.net cannot use the beacon: nothing in the update path is built for linux-arm64

The obvious way to auto-update this node is to install `dig-updater` and let the signed manifest
drive it, like every other DIG host. It is not available here, and the reason is worth recording
because the design keeps looking correct until someone checks the artifact lists:

- dig-updater's build matrix is `x86_64-pc-windows-msvc`, `x86_64-unknown-linux-gnu`,
  `aarch64-apple-darwin`, `x86_64-apple-darwin`. **No aarch64 Linux.** There is no beacon binary
  this host can execute.
- The live manifest's only Linux `dig-node` artifact is `dig-node_<v>_amd64.deb` — wrong
  architecture, and a `.deb` installed as the node binary bricks the host anyway.

This box is `t4g.small`, Graviton. Both gaps have to close upstream before the beacon is an option.

**Probing `updates.dig.net` will mislead you.** It is CloudFront over S3 with ListBucket denied, so
it answers **403 for anything missing, including a path that never existed** — `/v1/stable` 403s
while `/v1/stable/manifest.json` returns 200. A 403 there is not evidence of anything until you
control against a deliberately bogus path.

## An artifact's checksum says nothing about whether it runs here

The install path verifies SHA-256 before installing, which is the right gate and an incomplete one:
a correctly-named asset built for amd64 has a perfectly valid digest. Provenance and executability
are different claims. The update path now proves both — `file` must report an aarch64 ELF on the
runner, and the staged binary must answer `--version` on the host — before anything is swapped.

The same distinction explains why the asset name is **constructed** (`dig-node-<v>-linux-arm64`)
rather than searched for. A substring match on "arm64" also finds `dig-node_<v>_arm64.deb`, which
is the right architecture, the right project, the right version — and unbootable as `/usr/local/bin/dig-node`.

## A routine deploy must not replace the node, and the gateway port lives in exactly one place (#2034)

Two deploy defects with the same shape — a value copied instead of derived.

The post-deploy `verify-node.sh` hardcoded the gateway port (probing `8080`, later a hardcoded
`443`) while the gateway actually binds whatever `var.gateway_port` (canonically `443`) puts into the
unit's `GATEWAY_LISTEN`. A second literal copy is a drift waiting to happen, and it happened: every
healthy deploy reported RED. The port is now DERIVED on-host with
`systemctl show rpc-gateway.service --property=Environment` → parse `GATEWAY_LISTEN` → port after the
last colon. The canonical port lives once, in terraform; the code default `0.0.0.0:8080` is only the
dev fallback for when `GATEWAY_LISTEN` is unset, never the deployed value.

Separately, the gateway binary's SHA is templated into `user_data`, and a build is not
bit-reproducible, so even a rebuild of unchanged source changed `user_data` and — with
`user_data_replace_on_change = true` — Terminate+RunInstances'd the box on every deploy: ~2.5 min
public outage, plus the certificate-reissue failure mode that cost ~21h (#2037). The fix is the same
in-place mechanism the nightly node update already uses: terraform now holds the instance still
(`user_data_replace_on_change = false` + `ignore_changes = [user_data_base64]`), and `deploy.yml`
installs the freshly-built, checksum-verified gateway over SSM (`update-gateway.sh`, with a rollback
if it fails to serve). `user_data` remains the checksum-pinned bootstrap floor a FRESH instance
installs; a deliberate `terraform taint` must be followed by a deploy so the floor and the running
gateway reconverge.
