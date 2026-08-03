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

### Required AWS pre-requisite: the origin-certificate secret

The stack **reads** a Secrets Manager secret named `rpc.dig.net/origin-cert` and never creates it.
A plan fails with `couldn't find resource` if it is missing. Bootstrapping a fresh environment:

```bash
aws secretsmanager create-secret --name rpc.dig.net/origin-cert \
  --description "Origin certificate + certbot state for node-rpc.dig.net"
```

Leave it empty. The first boot finds nothing to restore, orders a certificate, and publishes it;
every boot after that restores. See "The certificate outlives the instance" below for why this is
deliberately outside terraform's ownership.

`DIG_NODE_*` are repo variables rather than terraform defaults on purpose: the running node
version is an operational decision, it is visible in the workflow run, and it can be rolled back
without a code change.

### The OIDC subject for this repo is NOT `repo:DIG-Network/rpc.dig.net`

Worth knowing before you debug an `AssumeRoleWithWebIdentity` denial for an hour. GitHub now issues
**immutable, ID-based subject prefixes to newly created repositories**, even when
`use_default: true` and `use_immutable_subject: false`:

```
$ gh api repos/DIG-Network/rpc.dig.net/actions/oidc/customization/sub
{"use_default":true,"use_immutable_subject":false,
 "sub_claim_prefix":"repo:DIG-Network@180309536/rpc.dig.net@1319851013"}

$ gh api repos/DIG-Network/hub.dig.net/actions/oidc/customization/sub      # older repo
{"use_default":true,"use_immutable_subject":false,
 "sub_claim_prefix":"repo:DIG-Network/hub.dig.net"}
```

So a trust policy copied from an older DIG repo will deny every assume. `rpc-dig-net-ci-deploy`
trusts **both** forms, scoped in each case to `:environment:production`, `:ref:refs/heads/main`,
and `:ref:refs/tags/*`.

Never widen that to a bare `repo:…:*`. The `pull_request` subject matches it, which would let a
workflow running on a **fork's** pull request assume the deploy role.

### Every deploy replaces the instance — on purpose

The gateway binary's SHA-256 is baked into `user_data`, so a new release changes `user_data`, which
replaces the EC2 instance. Immutable infrastructure, with the cost you would expect: a few minutes
of downtime while the new host boots, re-installs `dig-node`, and re-establishes the S3 mount.

What must **not** be replaced is `aws_ebs_volume.state`, because it holds the node's peer identity.
Its AZ is therefore read from the subnet, never from `aws_instance.node.availability_zone` — the
latter goes "known after apply" whenever a replace is planned, which cascades into replacing the
volume and trips its `prevent_destroy`. If you ever see *"Resource aws_ebs_volume.state has
lifecycle.prevent_destroy set, but the plan calls for this resource to be destroyed"*, something has
re-coupled the volume to the instance. Do not disable `prevent_destroy` to get past it — that guard
is the peer identity's last line of defence. Break the coupling instead.

### The certificate outlives the instance

A replacement must be **cheap**, and for a while it was not. The origin certificate used to live
only on the instance's disk, so every replacement bought a new one from Let's Encrypt instead of
reusing one. On 2026-08-03 the sixth replacement in a day hit the five-per-week limit for that
identifier set and the read tier was down for ~21 hours with no way to self-recover
(dig_ecosystem#2037). An instance replacement had quietly become an operation that consumes a
rate-limited external resource, and nothing said so.

The certificate now lives in Secrets Manager and the instance is the cache:

```
boot -> dig-origin-cert ensure
          restore from rpc.dig.net/origin-cert
            fresh?      -> done, Let's Encrypt is never contacted
            near expiry -> certbot renew -> publish -> restart the gateway
          nothing stored -> certbot certonly -> publish
```

`/usr/local/sbin/dig-origin-cert` is installed verbatim from `infra/dig-origin-cert.sh`, and
`certbot-renew.timer` runs it twice daily.

**Editing the helper replaces the instance — including a comment-only edit.** Its SHA-256 is pinned
into `user_data` by `filesha256`, and `user_data_replace_on_change = true`, so any byte that changes
in `infra/dig-origin-cert.sh` changes `user_data` and recycles the node. That is correct — the host
must run the version that was reviewed — but it means a typo fix in a comment costs a replacement.
Batch helper edits rather than trickling them.

**A publish failure is degraded, not down.** If `put-secret-value` fails, the host keeps serving and
logs a `WARNING` naming the cost: the durable copy still holds the previous certificate, so the next
replacement restores that, renews, and spends a rate-limited issuance — every time, until write
access is fixed. `grep WARNING` in the cloud-init log or the certbot-renew journal is how you find
it; there is no alarm yet.

**Two things must not be "tidied up".**

- The certificate carries a second name, `rpc-origin.dig.net`, with no DNS record. Let's Encrypt
  rate-limits per **exact set of identifiers**, and the single-name set is the one that was
  exhausted. Removing the second name puts issuance back on the burnt bucket.
- `data.aws_secretsmanager_secret.origin_cert` is a data source, not a resource. Terraform
  replaces the instance routinely; if it also owned the certificate, a taint or a destroy could
  take it, and re-creating one is not free.

**Diagnosing a certificate problem**

```bash
# what the host has, how long it is good for, and WHICH certificate it is
certbot certificates | grep -E 'Certificate Name|Serial Number|Domains|Expiry'

# what is stored (metadata only — never print the value, it contains the private key
# and the ACME account key)
aws secretsmanager describe-secret --secret-id rpc.dig.net/origin-cert

# how many generations this host has ever held — one file per issuance
ls /etc/letsencrypt/archive/node-rpc.dig.net/
```

**To prove a replacement did not issue, compare the SERIAL NUMBER, not a certificate count.** A
restored instance serves the *same* serial; one that ordered serves a new one. Three signals should
agree, and they are all local:

| signal | restored | re-issued |
|---|---|---|
| `certbot certificates` serial | unchanged | new |
| `/etc/letsencrypt/archive/…/` | `cert1.pem` only | `cert2.pem` appears |
| cloud-init log | `restored the origin certificate from …` | `ordering one from Let's Encrypt` |

A fourth: the secret's `VersionId` only changes when the host publishes, so a pure restore leaves it
alone.

crt.sh is the cross-check against Let's Encrypt itself rather than against our own records, but it
is not always reachable — it returned `502 Bad Gateway` throughout the #2037 recovery. Do not let a
verification plan depend on it:

```bash
curl -s -H 'User-Agent: dig-loop/1.0' 'https://crt.sh/?q=%25.dig.net&output=json' \
  | jq -r '.[] | "\(.not_before) \(.name_value)"' | sort -u
```

Certificates appear twice there (pre-certificate and certificate); de-duplicate before counting
against the limit of five.

If the limit is ever exhausted again, the restore path means a replacement no longer needs an
issuance at all — check the secret is populated before assuming otherwise. Adding another name to
the set is the escape hatch, not the first move.

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
| the node is a real peer | dial `node-rpc.dig.net:9444` from another node and complete an mTLS handshake |
| `9778` is not exposed | `nmap -Pn -p 9778 node-rpc.dig.net` from off-host must not connect |
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
