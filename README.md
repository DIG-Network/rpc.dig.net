# rpc.dig.net

The public DIG Network gateway. A **thin read-tier wrapper in front of a real `dig-node`** — not a
node, and not a simulation of one.

```
                    browsers                              peers
                       |                                    |
              https://rpc.dig.net                  node-rpc.dig.net:9444 (peer-RPC + DHT, mTLS)
                       |                           node-rpc.dig.net:9445 (gossip)
                  CloudFront                                |
                       |                                    |
        +--------------v------------------------------------v--------------+
        |  one EC2 host                                                     |
        |                                                                   |
        |   rpc-gateway  --loopback-->  dig-node                            |
        |   (this repo)   127.0.0.1:9778   |                                |
        |   read tier only                 |                                |
        |                                  v                                |
        |                    <cache>/modules  = S3, mounted READ-ONLY       |
        |                    <cache>/{downloads,responses,peer-net} = EBS   |
        +-------------------------------------------------------------------+
                                           |
                                  s3://dig-rpc-node-capsules
                                  {store_hex}/{root_hex}.dig
                                  written only by the hub's publish path
```

## The two ideas worth knowing

**1. The gateway is deny-by-default, in two dimensions.** The node's local surface on `9778` is
loopback-only for a reason — besides content reads it answers wallet JSON-RPC, a wallet WebSocket,
and `/s/*` *server-side-decrypted plaintext*. So the gateway is not a reverse proxy. Exactly one
route reaches the node (`POST /`), and a body reaches it only if **every** JSON-RPC call inside
names a method on the public-read allowlist. Batches are all-or-nothing. Unknown methods are
refused, not forwarded. See [`src/gate.rs`](src/gate.rs) — it is a pure function, and the test
suite drives it exhaustively.

**2. The capsule cache is S3, read-only, and that read-only is a security property.** `.dig`
capsules never land on the instance's disk; they are read through Mountpoint for S3. Because the
node cannot write to its own capsule store, "no maximum cache capacity" can never become unbounded
local growth — the cache is bounded by S3 and writable only by the hub. Only `<cache>/modules/` is
mounted; the rest of the cache tree stays on EBS because dig-node does `O_RDWR` + `seek` +
arbitrary-order writes in `downloads/`, which no S3 mount supports. `SPEC.md` §5.2 has the full
operation-by-operation table and the silent-failure trap that forces the split.

## Layout

| path | what |
|---|---|
| `src/tier.rs` | the method→tier table — the allowlist, and why each exclusion is excluded |
| `src/jsonrpc.rs` | minimal envelope reading: which methods does this body call? |
| `src/gate.rs` | the decision. Pure, no I/O |
| `src/bin/gateway.rs` | the axum process: routes, CORS, limits, loopback forward |
| `infra/` | terraform — the node host, the capsule bucket, the security group, DNS |
| `SPEC.md` | the normative contract |
| `runbooks/` | deploy + run-locally |

## Develop

```bash
cargo test --all-targets                        # the gate, exhaustively
cargo clippy --all-targets -- -D warnings
cargo run --features server --bin gateway       # needs a dig-node on 127.0.0.1:9778
```

`DIG_NODE_URL` points the gateway at a node; it must be loopback in production.

## Cost

See `runbooks/deploy.md` for the itemised monthly figure and the levers.
