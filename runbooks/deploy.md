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
| variable | `DIG_NODE_VERSION` | dig-node tag a fresh instance boots on — **maintained automatically**, see "Node auto-update" |
| variable | `DIG_NODE_ARTIFACT_URL` | linux-arm64 dig-node binary URL for that tag (maintained automatically) |
| variable | `DIG_NODE_SHA256` | its SHA-256 (maintained automatically) |
| variable | `DIG_NODE_AUTOUPDATE` | unset or anything but `off` = nightly updates on; `off` = schedule disabled |
| secret | `RELEASE_TOKEN` | PAT that pushes the changelog commit + tag, **and writes the three `DIG_NODE_*` variables** (`GITHUB_TOKEN` cannot) |
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

### A routine deploy does NOT replace the instance (dig_ecosystem#2034)

The gateway binary's SHA-256 is baked into `user_data`, and a build is not bit-reproducible, so a
new release always changes `user_data`. It used to replace the whole EC2 instance for that
(`user_data_replace_on_change = true`): ~2.5 min of public outage per deploy, a `dnf -y update`
against an unpinned input, and the certificate-restore path exercised on every release. Terraform now
leaves the instance **still** — `user_data_replace_on_change = false` and
`ignore_changes = [user_data_base64]` on `aws_instance.node` — and `deploy.yml` installs the
freshly-built, checksum-verified gateway **in place** over SSM (`.github/update-gateway.sh`), swapping
one binary and restarting `rpc-gateway`, with a rollback to the previous binary if the new one does
not serve. This is the same in-place mechanism the nightly `dig-node` update uses.

`user_data` remains the **checksum-pinned bootstrap floor** a FRESH instance installs at boot. Because
it is ignored for diffing, a **deliberate** replacement (`terraform taint aws_instance.node`, or an AMI
refresh) boots from the floor's value at create time and may install an older gateway — so **follow a
deliberate replacement with a deploy** (or a manual `update-gateway.sh` run) to reconverge the running
gateway with the latest release. Manual rollback of a healthy-but-wrong gateway build is a rename:
`mv /usr/local/bin/rpc-gateway.rollback /usr/local/bin/rpc-gateway && systemctl restart rpc-gateway`.

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

**Editing the helper changes `user_data` but no longer recycles the node.** Its SHA-256 is pinned into
`user_data` by `filesha256`, so any byte that changes in `infra/dig-origin-cert.sh` changes
`user_data` — but `user_data_base64` is now ignored for diffing (above), so a running instance is left
untouched and keeps the previously-installed helper until it is next replaced. If a helper change must
reach the running host immediately, install it there deliberately (over SSM, the same way the gateway
is) or `terraform taint aws_instance.node` to rebuild from the new floor.

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

## Node auto-update

`.github/workflows/auto-update-node.yml` keeps the dig-node on the newest **stable** dig-node
release. It exists because the node sat on `v0.84.0` while dig-node's main was at `0.93.9` — nine
minor versions, including the fix for a live `*.on.dig.net` outage. Nothing was broken:
`modules/apps` cuts stable tags by manual dispatch only, and nothing drove the manual step
(dig_ecosystem#2073).

### How it triggers

- **Nightly at 07:17 UTC.** Clear of the certbot renewal timer (03:00/15:00 ±1h) and of dig-node's
  midnight-UTC nightly build. Not on the hour, because GitHub's scheduler is contended there.
- **Manually**, any time: `gh workflow run auto-update-node.yml --repo DIG-Network/rpc.dig.net`.

```
newest stable dig-node release  (src/release.rs: no prereleases, numeric ordering,
                                 the raw linux-arm64 asset by exact name, canonical URL)
  -> download it on the runner, sha256 THE BYTES, reject anything that is not an aarch64 ELF
  -> over SSM: verify the checksum on the host, prove the binary runs, keep the old one,
     swap, restart dig-node + rpc-gateway, prove it serves, ROLL BACK if it does not
  -> re-run .github/verify-node.sh (mount, allowlist boundary, peer ports, listener set)
  -> move DIG_NODE_VERSION / _ARTIFACT_URL / _SHA256 to what is now running
  -> confirm https://rpc.dig.net/ reports the new version
```

**It never runs `terraform apply`.** deploy.yml is still the one writer of AWS resources; this
workflow changes one binary and two systemd units. The two share the `deploy-rpc-dig-net`
concurrency group so they can never overlap.

**Why not a full redeploy.** An apply replaces the instance (the version is inside user_data), and
a replacement re-runs `dnf -y update` and re-restores the origin certificate. A restore failure
falls through to ordering a certificate, and there are five per week — exhausting them is
dig_ecosystem#2037, ~21 hours down. Nightly replacement puts that on a timer.

**Why the variables move too.** `DIG_NODE_VERSION` is the bootstrap floor: what a *fresh* instance
installs. If the host advanced and the variable did not, the next deploy would silently revert the
node (dig_ecosystem#2034). They move together, only after the host is verified healthy.

### Turn it off in a hurry

```bash
gh variable set DIG_NODE_AUTOUPDATE --repo DIG-Network/rpc.dig.net --body off
```

Effective at the next scheduled tick; nothing else changes and the node keeps running. This stops
the **schedule only** — a manual dispatch still works, deliberately, because the fastest way out of
a bad release is a rollback and disabling updates must not disable that too.

Belt and braces, if the schedule must not fire at all:
`gh workflow disable auto-update-node.yml --repo DIG-Network/rpc.dig.net`.

Re-enable with `gh variable set DIG_NODE_AUTOUPDATE --body on` (any value but `off` works;
deleting the variable also works).

### Roll back to a specific version

Two ways, fastest first.

**1. On the host, seconds, no network.** The binary that was replaced is still there:

```bash
aws ssm start-session --target <instance-id>
sudo mv /usr/local/bin/dig-node.rollback /usr/local/bin/dig-node
sudo systemctl restart dig-node && sudo systemctl start rpc-gateway
curl -s localhost:9778 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"dig.health"}'
```

This does NOT update `DIG_NODE_VERSION`, so turn the schedule off first or the next run puts the
newer release straight back. Follow it with option 2 to make the rollback durable.

**2. Through the workflow — durable, and the one to use.** Naming a version is the only way to
install an older release; automatic selection is newest-wins and cannot go backwards.

```bash
gh variable set DIG_NODE_AUTOUPDATE --repo DIG-Network/rpc.dig.net --body off
gh workflow run auto-update-node.yml --repo DIG-Network/rpc.dig.net -f version=v0.84.0
gh run watch "$(gh run list --workflow auto-update-node.yml --limit 1 --json databaseId -q '.[0].databaseId')"
```

It runs the same gates — checksum from the bytes, aarch64 check, on-host verification, rollback if
it does not serve — and leaves the three variables naming `v0.84.0`, so a later instance
replacement boots on it too. Leave `DIG_NODE_AUTOUPDATE=off` until the bad release is superseded,
otherwise the next nightly moves forward again.

Rehearse without touching anything:
`gh workflow run auto-update-node.yml -f dry_run=true` resolves the release and computes the
checksum, then stops before the host is contacted.

### When it fails

A failed update leaves the node **running** — that is the design, and the workflow going red is
the only symptom you should see. Read the run's on-host output; it names which gate stopped it.

| the log says | what happened | what to do |
|---|---|---|
| `sha256sum: WARNING` | the download did not match the digest taken from the bytes the runner fetched | nothing was installed; re-run. Twice in a row means the release assets changed under the tag — do not bypass it |
| `REFUSING: … is not an aarch64 ELF` | the release published something other than a raw arm64 executable in that slot | nothing was contacted; fix it upstream in dig-node |
| `REFUSING: … is older than` | someone asked for a downgrade without naming it as one | use `-f version=…`, which permits it deliberately |
| `ROLLED BACK` | the release installed but never served; the previous binary is back | the node is fine. Set `DIG_NODE_AUTOUPDATE=off` so the nightly stops retrying, and report the release |
| `CRITICAL: rollback … did not restore service` | **the tier is down** | this is the one that needs a human — go to the host over SSM, check `journalctl -u dig-node -u rpc-gateway`, and use rollback option 1 |
| `expected exactly one running node` | a deploy is mid-flight, or something else carries the node's tags | wait for the deploy, then re-run |
| `rpc.dig.net never reported <version>`, after `VERIFIED` on the host | **the update SUCCEEDED**; the node is on the new release and the host verified it. Only the public hop disagrees | do not roll back. The variables have already moved and are correct. Check CloudFront and the origin hop — `curl -sI https://rpc.dig.net/` and the `node-rpc.dig.net` A record — then confirm with the `dig.health` one-liner below |

Do not judge this by the workflow badge alone — judge the endpoint:

```bash
curl -s https://rpc.dig.net/ -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"dig.health"}' | jq -r .result.version
```

### The beacon is the eventual home for this

Every other DIG host updates through **dig-updater** — the beacon, a scheduled run of dig-updater
itself, trust-rooted on the pinned `BEACON_ROOT_PUBKEY_B64` and reading the signed manifest at
`https://updates.dig.net/v1/stable/manifest.json`. This host does not, for one reason: **there is
no linux-arm64 build of anything involved.** dig-updater's release matrix is
`x86_64-pc-windows-msvc`, `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`, `x86_64-apple-darwin`
— no aarch64 Linux — and the live manifest's only Linux dig-node artifact is
`dig-node_<v>_amd64.deb`. This host is Graviton. There is no beacon binary it can run and no
artifact the beacon could install on it.

When dig-updater ships linux-arm64 and the manifest carries a linux-arm64 dig-node artifact, this
workflow should be replaced by installing the beacon — with one thing kept: whatever updates the
node must still move `DIG_NODE_VERSION`, or an instance replacement reverts it (dig_ecosystem#2034).

Probing note: `updates.dig.net` is CloudFront over S3 with ListBucket denied, so it answers **403
for anything missing, including a path that never existed**. `/v1/stable` 403s while
`/v1/stable/manifest.json` returns 200. Never read a 403 there as "the feed is broken" — control
against a deliberately bogus path first.

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
