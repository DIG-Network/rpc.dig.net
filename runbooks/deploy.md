# Runbook — rpc.dig.net

## Deploy

One writer, one path. `.github/workflows/deploy.yml` on a `v*` tag is the **only** thing that
applies this stack. Nothing is changed in the console — see dig_ecosystem#1936, where hand-made
relay settings drifted invisibly from terraform for an unknown length of time, and #1938, where two
pipelines deploying one service silently undid each other.

```
merge to main -> release.yml cuts vX.Y.Z -> deploy.yml:
    build gateway (aarch64) -> publish release asset -> sha256
    -> terraform apply (asset URL + sha pinned into user_data)
    -> poll /health until the gateway answers
```

### Required repo configuration

| kind | name | value |
|---|---|---|
| variable | `CI_DEPLOY_ROLE_ARN` | OIDC deploy role for this repo |
| variable | `TF_STATE_BUCKET` | shared terraform state bucket |
| variable | `TF_LOCK_TABLE` | shared terraform lock table |
| variable | `DIG_NODE_VERSION` | pinned dig-node tag, e.g. `v0.65.0` |
| variable | `DIG_NODE_ARTIFACT_URL` | linux-aarch64 dig-node binary URL for that tag |
| variable | `DIG_NODE_SHA256` | its SHA-256 |
| secret | `RELEASE_TOKEN` | PAT that pushes the changelog commit + tag |
| environment | `production` | gates the apply |

`DIG_NODE_*` are repo variables rather than terraform defaults on purpose: the running node
version is an operational decision, it is visible in the workflow run, and it can be rolled back
without a code change.

### Changing a setting safely

Edit the `.tf` file, open a PR, let CI run `terraform validate`, merge. Never `aws ... modify` a
live resource — a change made outside terraform is invisible in review and will be silently
reverted or silently preserved forever depending on which resource it is.

## Run locally

The gateway alone, against a node you already run:

```bash
cargo run --features server --bin gateway
# GATEWAY_LISTEN=127.0.0.1:8080  DIG_NODE_URL=http://127.0.0.1:9778
curl -s localhost:8080/health
curl -s localhost:8080 -X POST -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"dig.health"}'
# a restricted method must come back -32601:
curl -s localhost:8080 -X POST -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"control.status"}'
```

## Operate

Management is **SSM Session Manager**. There is no SSH and no port 22.

```bash
aws ssm start-session --target "$(terraform -chdir=infra output -raw node_instance_id)"

systemctl status dig-capsules dig-node rpc-gateway
journalctl -u dig-node -n 100
mountpoint /var/lib/dig-node/cache/modules     # must report "is a mountpoint"
ls /var/lib/dig-node/cache/modules             # the published capsules, served from S3
```

### Health checks that actually prove something

| claim | how to prove it |
|---|---|
| the capsule store is S3, not disk | `df -h /var/lib/dig-node/cache/modules` shows the FUSE mount; `du -sh` on the EBS root does not grow when a capsule is served |
| the node is a real peer | dial `node.dig.net:9444` from another node and complete an mTLS handshake |
| `9778` is not exposed | `nmap -Pn -p 9778 node.dig.net` from off-host must not connect |
| the read tier is CloudFront-only | the gateway port must refuse a direct connection from an arbitrary host |
| a restricted method is unreachable | `POST` `control.status` through the public URL returns `-32601` |

## Cost

us-east-1 on-demand, as configured (t4g.small):

| item | monthly |
|---|---|
| EC2 t4g.small, 730 h @ $0.0168 | $12.26 |
| gp3 root, 12 GB @ $0.08 | $0.96 |
| gp3 state volume, 8 GB @ $0.08 | $0.64 |
| public IPv4 address, 730 h @ $0.005 | $3.65 |
| S3 Standard, ~6 GB of capsules @ $0.023 | $0.14 |
| S3 GET requests (~1 M) | ~$0.40 |
| S3 -> EC2 in-region, via the gateway endpoint | $0.00 |
| **base total** | **≈ $18 / month** |

Plus egress to the internet: the first 100 GB/month is free, then $0.09/GB. Peer serving and
CloudFront origin fetches both land here, and at real traffic this is the term that dominates —
not the instance.

**The storage tier that produced the number:** S3 Standard, read in-region through a VPC gateway
endpoint. EFS was rejected at roughly 7× the per-GB price; an EBS-backed unbounded cache would have
been unbounded cost on the most expensive storage in the account.

### Levers, honestly stated

| lever | saves | cost of pulling it |
|---|---|---|
| `t4g.micro` instead of `t4g.small` | $6.13/mo | 1 GiB RAM. dig-node reads a whole ~135 MiB capsule into memory to serve it and keeps a 256 MiB decoded LRU. Fits only with swap, and swapping during a capsule decode is the wrong place to save six dollars |
| drop the public IPv4, IPv6-only | $3.65/mo | v4-only peers can no longer reach the node |
| 1-year Compute Savings Plan | ~40% of the instance | commitment |

The instance is the small term. Do not optimise it before egress.
