#!/usr/bin/env bash
#
# dig-origin-cert — owns the lifecycle of rpc.dig.net's origin TLS certificate.
#
# THE PROBLEM THIS SOLVES (dig_ecosystem#2037). The certificate used to live only on
# instance-local disk, and Terraform replaces this instance on every deploy. So a deploy did not
# *reuse* a certificate, it *bought* one — and on 2026-08-03 the sixth replacement in a day hit
# Let's Encrypt's five-per-week limit for the exact identifier set. The gateway exits when the
# cert file is missing, so the read tier was hard down for ~21 hours with no way to self-recover.
# An instance replacement had quietly become an operation that consumes a scarce external
# resource, and nothing in the system said so.
#
# THE IDEA. Invert which copy is authoritative. The durable certificate lives in Secrets Manager;
# the one on local disk is a cache that a replacement refills. Let's Encrypt is then contacted
# only for the two things that genuinely need it — a first certificate, and a real renewal — so
# the rate limit stops being reachable by deploying.
#
# TWO RULES EVERY BRANCH HERE OBEYS.
#
#   1. **Never order a certificate on an unknown state.** Ordering is the expensive, rate-limited
#      act, so it happens only once this script has positively established that no certificate is
#      available — not merely that it failed to find one. A failed API call, a throttle, an IAM
#      permission still propagating: none of those may lead to an order.
#
#   2. **The stored payload is UNTRUSTED INPUT.** The node's own role can write that secret, so an
#      attacker who reaches the unprivileged `dignode` account can replace it. This script then
#      unpacks it as root and hands it to certbot, which also runs as root — and, because a
#      replacement instance restores the same payload, anything smuggled in would survive the one
#      remediation this stack has. So the archive is validated, stripped and normalised before it
#      is allowed anywhere near /etc, and certbot is told never to run directory hooks.
#
# WHAT IS STORED, AND WHY IT IS THE WHOLE STATE. The payload is a gzipped tar of certbot's state
# directories, not just the two PEM files. certbot needs its renewal config, its archive and its
# ACME account to renew; restoring only the PEMs would serve traffic today and then silently stop
# renewing, which fails ~60 days later, far from whatever caused it. It carries only the
# directories certbot owns — never `renewal-hooks/`, which exists to execute things.
#
# KEY-MATERIAL DISCIPLINE. The private key moves host <-> Secrets Manager and never through a log
# line, an argument list, or a command's stdout. `set -x` is deliberately not enabled here even
# though the bootstrap that calls this script runs under it.

set -euo pipefail

# --- Configuration, all supplied by the bootstrap ---------------------------------------------
#
# Named identifiers only; nothing secret lives in the environment.

readonly SECRET_ID="${DIG_ORIGIN_CERT_SECRET:?the Secrets Manager secret id must be set}"
readonly PEER_HOST="${DIG_ORIGIN_CERT_HOST:?the primary certificate hostname must be set}"
readonly SAN_HOST="${DIG_ORIGIN_CERT_SAN:?the second certificate hostname must be set}"
readonly REGION="${AWS_DEFAULT_REGION:?the AWS region must be set}"

# Overridable so the test suite can drive this script against a sandbox instead of the real
# system directory. Production never sets it.
readonly STATE_DIR="${DIG_ORIGIN_CERT_STATE_DIR:-/etc/letsencrypt}"
readonly LIVE_DIR="$STATE_DIR/live/$PEER_HOST"

# The group that may read the live certificate. The gateway runs unprivileged and joins it.
# Overridable only so the tests can name a group they already belong to; production never sets it.
readonly CERT_GROUP="${DIG_ORIGIN_CERT_GROUP:-certaccess}"

# Ownership imposed on restored state, replacing whatever the archive claimed. Overridable for the
# same reason: the tests are not root and cannot chown to it. Production never sets it.
readonly STATE_OWNER="${DIG_ORIGIN_CERT_OWNER:-root:root}"

# The only top-level entries certbot owns, and therefore the only ones the payload may carry.
# `renewal-hooks/` is deliberately absent: its whole purpose is to hold scripts certbot executes
# as root, which is exactly what an attacker who can write the secret would put there.
readonly CERTBOT_STATE_DIRS=(live archive renewal accounts csr keys)

# certbot's own renewal threshold. Matching it means a certificate restored inside the window is
# renewed at boot rather than waiting for the timer's next run.
readonly RENEW_WITHIN_DAYS=30

# Secrets Manager accepts 65 536 bytes; stop well short so the failure is a clear message here
# rather than an API error at the worst possible moment. A single certificate encodes to ~8.5 KB,
# so this is roughly seven times the real size.
readonly MAX_ENCODED_BYTES=60000

# What that payload is allowed to become. 64 KB of gzip can expand to something far larger, and
# restore unpacks into /etc before anything has judged the contents; this bounds the damage a
# deliberately compressible payload can do to the root filesystem. Real state is ~50 KB.
readonly MAX_DECOMPRESSED_BYTES=$((8 * 1024 * 1024))

# How a restore attempt ended. Three outcomes and not two, because ABSENT and FAILED demand
# OPPOSITE responses: one may lead to an order, the other must never.
readonly RESTORE_OK=0
readonly RESTORE_ABSENT=1 # positively established that nothing usable is stored
readonly RESTORE_FAILED=2 # could not establish anything — the state is unknown

# Backoff between attempts to read the secret. Overridable only so the tests that exercise the
# unreadable-secret path do not spend fifteen seconds sleeping; production never sets it.
readonly RETRY_DELAY_SECONDS="${DIG_ORIGIN_CERT_RETRY_DELAY:-5}"

WORK="$(mktemp -d)"
readonly WORK
chmod 700 "$WORK"

# Staging is a sibling of the state directory so installing it is an atomic rename (see
# install_state). Only staging is cleaned up on exit: if a rollback ever fails, the displaced
# original is the last copy of the certificate and must survive for an operator to recover.
readonly STAGING="$STATE_DIR.restoring-$$"
readonly DISPLACED="$STATE_DIR.replaced-$$"
trap 'rm -rf "$WORK" "$STAGING"' EXIT

log() {
  printf '%s dig-origin-cert: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2
}

die() {
  log "$*"
  exit 1
}

# --- Reading the certificate on disk -----------------------------------------------------------

# A certificate and a key that parse, and that belong to each other.
#
# "Non-empty" is not "a certificate". A one-byte fullchain.pem passes a `-s` test, replaces working
# state, and hands systemd a gateway that exits at startup — the crash loop this whole change
# exists to make impossible. Parsing both halves and matching their public keys is what makes
# "there is a usable certificate here" an honest claim.
pem_pair_is_usable() {
  local dir="$1" cert_pubkey key_pubkey
  cert_pubkey="$(openssl x509 -in "$dir/fullchain.pem" -noout -pubkey 2>/dev/null)" || return 1
  key_pubkey="$(openssl pkey -in "$dir/privkey.pem" -pubout 2>/dev/null)" || return 1
  [ -n "$cert_pubkey" ] && [ "$cert_pubkey" = "$key_pubkey" ]
}

certificate_is_present() {
  pem_pair_is_usable "$LIVE_DIR"
}

# True while the certificate has not yet expired — the bar for "can still serve traffic".
certificate_is_valid_now() {
  openssl x509 -in "$LIVE_DIR/cert.pem" -noout -checkend 0 >/dev/null 2>&1
}

# True while the certificate has more than RENEW_WITHIN_DAYS of life left.
certificate_is_fresh() {
  openssl x509 -in "$LIVE_DIR/cert.pem" -noout \
    -checkend "$((RENEW_WITHIN_DAYS * 86400))" >/dev/null 2>&1
}

certificate_expiry() {
  openssl x509 -in "$LIVE_DIR/cert.pem" -noout -enddate 2>/dev/null || echo "notAfter=unknown"
}

# A stable identity for "which certificate is this", used to tell a real renewal from a no-op.
certificate_fingerprint() {
  openssl x509 -in "$LIVE_DIR/cert.pem" -noout -fingerprint -sha256 2>/dev/null || echo absent
}

# The gateway runs unprivileged, so it needs group read on the live certificate — without opening
# the whole archive, so the private keys of any other certificate on this host stay unreadable.
#
# Re-applied after every change rather than only at boot: certbot writes each renewed certificate
# root-only, so a renewal that did not re-apply this would leave the gateway unable to read the
# very certificate it was just restarted to pick up. That failure would land ~60 days after anyone
# last touched this.
#
# `chgrp -h` so a symlink's own group changes rather than its target's — otherwise a restored
# archive could point a `live/` entry at any root-owned file and hand its group away.
apply_gateway_access() {
  getent group "$CERT_GROUP" >/dev/null || groupadd -f "$CERT_GROUP"

  # Only the directories that exist: certbot creates `archive/` when it writes its first
  # certificate, so on a host that has only ever restored, or during a first issue, it may not be
  # there yet. Naming a missing path here would abort the whole bootstrap over nothing.
  # `! -L` is the load-bearing half. `chmod -R` ignores symlinks it meets during traversal but
  # FOLLOWS one named on the command line, so a restored `archive -> /` would have had root run
  # `chmod -R g+rX /` across the whole host. `-d` alone does not catch it: it follows the link too.
  local dir
  for dir in "$STATE_DIR/live" "$STATE_DIR/archive"; do
    [ -d "$dir" ] && [ ! -L "$dir" ] || continue
    chgrp -h -R "$CERT_GROUP" "$dir"
    chmod -R g+rX "$dir"
  done
}

# --- restore ------------------------------------------------------------------------------------

# Fetch the stored payload into "$1". Returns one of the three RESTORE_* outcomes.
#
# Telling "the secret has no version" apart from "the call did not succeed" is the whole job here.
# Collapsing them into one "nothing stored" is what would let a throttle, an AccessDenied while an
# IAM policy is still propagating, or a network blip spend one of five weekly issuances.
fetch_stored_payload() {
  local into="$1" attempt
  for attempt in 1 2 3; do
    if aws secretsmanager get-secret-value \
      --region "$REGION" --secret-id "$SECRET_ID" \
      --query SecretString --output text >"$into" 2>"$WORK/aws.err"; then
      return "$RESTORE_OK"
    fi

    # Both "no such secret" and "no value for staging label AWSCURRENT" report this, and both are
    # definite: there is genuinely nothing to restore.
    if grep -q "ResourceNotFoundException" "$WORK/aws.err"; then
      log "the secret holds no certificate yet"
      return "$RESTORE_ABSENT"
    fi

    log "could not read $SECRET_ID (attempt $attempt of 3): $(tail -1 "$WORK/aws.err")"
    if [ "$attempt" -lt 3 ]; then
      sleep "$((attempt * RETRY_DELAY_SECONDS))"
    fi
  done
  return "$RESTORE_FAILED"
}

# Every member of the archive names a path certbot owns, inside the tree.
#
# tar refuses `..` members already, but this validates rather than inherits, and it adds the check
# tar cannot make: that the archive contains ONLY certbot's own state. A payload that also carried
# `renewal-hooks/pre/x.sh` would look like a certificate and execute as root at the next renewal.
archive_names_are_permitted() {
  local member top
  while IFS= read -r member; do
    member="${member#./}"
    [ -n "$member" ] && [ "$member" != "." ] || continue

    case "$member" in
    /* | ../* | */../* | */..)
      log "the stored archive names a member outside the state directory: $member"
      return 1
      ;;
    esac

    top="${member%%/*}"
    case " ${CERTBOT_STATE_DIRS[*]} " in
    *" $top "*) ;;
    *)
      log "the stored archive contains '$member', which is not certbot state"
      return 1
      ;;
    esac
  done < <(tar -tf "$WORK/state.tar")
}

# Nothing in the unpacked tree escapes it, and nothing in it can escalate.
#
# Symlink targets are resolved rather than pattern-matched, because certbot's own `live/` entries
# are legitimately relative and full of `..` (`../../archive/<host>/fullchain1.pem`) — the question
# is never whether a target contains `..`, only where it lands.
staged_tree_is_contained() {
  local link target offender

  offender="$(find "$STAGING" ! -type f ! -type d ! -type l -print -quit)"
  if [ -n "$offender" ]; then
    log "the stored archive contains a special file: $offender"
    return 1
  fi

  offender="$(find "$STAGING" -perm /6000 -print -quit)"
  if [ -n "$offender" ]; then
    log "the stored archive contains a setuid or setgid file: $offender"
    return 1
  fi

  while IFS= read -r link; do
    # Resolve the LINK, never `dirname + readlink`. Reconstructing the path that way turns an
    # absolute target into `$STAGING/live//etc/shadow`, and realpath then collapses the double
    # slash to something inside the tree — so `-> /etc/shadow` was read as `live/etc/shadow` and
    # accepted, while the far more exotic `-> ../../../etc/shadow` was correctly rejected.
    target="$(realpath -m --relative-to="$STAGING" "$link")"
    case "$target" in
    /* | .. | ../*)
      log "the stored archive has a symlink pointing outside the state directory: $link"
      return 1
      ;;
    esac
  done < <(find "$STAGING" -type l)
}

# Reduce every restored renewal config to keys we recognise, using certbot's OWN parser.
#
# certbot runs any hook named in a renewal config as root — `pre_hook` fires before the ACME
# exchange even happens, and the timer re-runs it twice a day — so a poisoned archive must not be
# able to carry one. Two decisions here, both learned the hard way:
#
# PARSE, DO NOT PATTERN-MATCH. The obvious version of this is a regex that deletes `*_hook =`
# lines. It does not work, because certbot reads these files with configobj, whose grammar accepts
# a QUOTED key and unquotes it: `'pre_hook' = …` is a bare `pre_hook` to certbot and invisible to
# the regex. Any text-level filter can disagree with the real parser about what a key even is, so
# this uses the real parser — the same configobj certbot imports — and the question stops being
# "does this line look like a hook".
#
# ALLOWLIST, DO NOT DENYLIST. Removing the hook keys we know about only bans the variants someone
# thought of. Everything outside the recognised set is dropped instead, so a hook key added by a
# future certbot, spelled unusually, or hidden in a nested section is gone without anyone having to
# predict it. Dropping is deliberate over rejecting: an unknown key cannot execute anything once it
# is gone, whereas refusing the payload would strand a replacement with no certificate.
#
# Fails CLOSED. If the parser is unavailable or a config will not parse, the payload is refused
# rather than installed unexamined.
sanitize_renewal_configs() {
  python3 - "$STAGING/renewal" <<'PYTHON' || return 1
import os
import re
import shutil
import sys

try:
    from configobj import ConfigObj
except ImportError:
    print("configobj is unavailable, so a renewal config cannot be examined", file=sys.stderr)
    raise SystemExit(1)

renewal_dir = sys.argv[1]
if not os.path.isdir(renewal_dir):
    raise SystemExit(0)

# Everything certbot writes for this deployment. A key outside these sets is not something the
# renewal needs, and dropping it is always safe.
TOP_LEVEL = {"version", "archive_dir", "cert", "privkey", "chain", "fullchain"}
RENEWAL_PARAMS = {
    "account", "authenticator", "installer", "server", "key_type", "elliptic_curve",
    "rsa_key_size", "must_staple", "reuse_key", "dns_route53_propagation_seconds",
}
CONFIG_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\.conf$")

dropped = []

for name in sorted(os.listdir(renewal_dir)):
    path = os.path.join(renewal_dir, name)

    # A name certbot would never read is a name that exists to hide something. Note certbot's own
    # glob skips dot-files, so `.evil.conf` would sit on disk unexamined by any name-based filter.
    if os.path.islink(path) or not os.path.isfile(path) or not CONFIG_NAME.match(name):
        shutil.rmtree(path, ignore_errors=True) if os.path.isdir(path) else os.remove(path)
        dropped.append("file %s" % name)
        continue

    try:
        config = ConfigObj(path, file_error=True)
    except Exception as exc:
        print("renewal config %s does not parse: %s" % (name, exc), file=sys.stderr)
        raise SystemExit(1)

    for key in list(config.scalars):
        if key not in TOP_LEVEL:
            del config[key]
            dropped.append("%s: %s" % (name, key))

    for section in list(config.sections):
        if section != "renewalparams":
            del config[section]
            dropped.append("%s: [%s]" % (name, section))
            continue
        params = config[section]
        for key in list(params.scalars):
            if key not in RENEWAL_PARAMS:
                del params[key]
                dropped.append("%s: [renewalparams] %s" % (name, key))
        for nested in list(params.sections):
            del params[nested]
            dropped.append("%s: [renewalparams][%s]" % (name, nested))

    config.write()

for item in dropped:
    print(item)
PYTHON
}

# Swap the staged directory into place.
#
# Both moves are renames within the same parent directory, so each is atomic: there is no moment
# where the state directory is half-written. Unpacking under /tmp instead would make this a
# cross-filesystem copy-then-delete, whose failure leaves exactly the both-copies-gone state this
# is written to prevent.
install_state() {
  if [ -e "$STATE_DIR" ] && ! mv "$STATE_DIR" "$DISPLACED"; then
    log "could not set the existing state directory aside"
    return 1
  fi
  if ! mv "$STAGING" "$STATE_DIR"; then
    if [ -d "$DISPLACED" ] && [ ! -e "$STATE_DIR" ] && mv "$DISPLACED" "$STATE_DIR"; then
      log "could not install the restored state; the previous one is back in place"
    else
      log "could not install the restored state; the previous one is at $DISPLACED — recover it"
    fi
    return 1
  fi
  rm -rf "$DISPLACED"
}

# Replace the local certbot state with the copy in Secrets Manager.
#
# Everything is validated in staging before anything on disk is touched, because restore replaces
# the state directory wholesale and a truncated, wrong-shaped or hostile payload must not be able
# to leave the host with neither the stored certificate nor the one it was already serving.
restore() {
  local outcome
  if fetch_stored_payload "$WORK/payload.b64"; then
    outcome="$RESTORE_OK"
  else
    outcome=$?
  fi
  [ "$outcome" -eq "$RESTORE_OK" ] || return "$outcome"
  chmod 600 "$WORK/payload.b64"

  # From here the payload exists but may be unusable. That is a definite, non-transient answer, so
  # it reports ABSENT: the caller is free to fall back, including to ordering a certificate.
  if [ ! -s "$WORK/payload.b64" ]; then
    log "the stored certificate is empty"
    return "$RESTORE_ABSENT"
  fi
  if ! base64 -d <"$WORK/payload.b64" >"$WORK/state.tar.gz" 2>/dev/null; then
    log "the stored certificate is not valid base64"
    return "$RESTORE_ABSENT"
  fi

  # Decompress ONCE, under a hard ceiling, before anything reads the contents. Reading one byte
  # past the ceiling is how an overflow is detected; a payload that hits it is refused rather than
  # unpacked into /etc. Everything downstream works from this plain tar.
  gzip -dc "$WORK/state.tar.gz" 2>/dev/null |
    head -c "$((MAX_DECOMPRESSED_BYTES + 1))" >"$WORK/state.tar" || true
  if [ "$(wc -c <"$WORK/state.tar")" -gt "$MAX_DECOMPRESSED_BYTES" ]; then
    log "the stored certificate expands past the $MAX_DECOMPRESSED_BYTES byte ceiling"
    return "$RESTORE_ABSENT"
  fi
  if ! archive_names_are_permitted; then
    return "$RESTORE_ABSENT"
  fi

  # Ownership and modes come from THIS host, never from the archive.
  rm -rf "$STAGING"
  mkdir -p "$STAGING"
  chmod 700 "$STAGING"
  if ! tar -xf "$WORK/state.tar" -C "$STAGING" \
    --no-same-owner --no-same-permissions --no-xattrs --no-acls 2>/dev/null; then
    log "the stored certificate is not a readable gzipped tar"
    return "$RESTORE_ABSENT"
  fi
  if ! staged_tree_is_contained; then
    return "$RESTORE_ABSENT"
  fi
  if ! pem_pair_is_usable "$STAGING/live/$PEER_HOST"; then
    log "the stored archive holds no usable certificate for $PEER_HOST"
    return "$RESTORE_ABSENT"
  fi

  local dropped
  if ! dropped="$(sanitize_renewal_configs)"; then
    log "the stored archive holds a renewal config that cannot be examined"
    return "$RESTORE_ABSENT"
  fi
  if [ -n "$dropped" ]; then
    log "dropped unrecognised renewal-config entries: $(echo "$dropped" | tr '
' ';')"
  fi

  chown -R "$STATE_OWNER" "$STAGING"
  find "$STAGING" -type d -exec chmod 700 {} +
  find "$STAGING" -type f -exec chmod 600 {} +

  install_state || return "$RESTORE_FAILED"
  apply_gateway_access
  log "restored the origin certificate from $SECRET_ID"
}

# --- save ----------------------------------------------------------------------------------------

# Publish the local certbot state so the next instance can restore it.
#
# Only the directories certbot owns go in, so the payload can never carry a hook, and the restore
# side's allowlist has nothing legitimate to reject.
#
# The payload reaches the API as a file reference, never as an argument: anything on a command
# line is readable by every process on the host through /proc, and this box is internet-facing.
save() {
  certificate_is_present ||
    die "refusing to publish: there is no usable certificate at $LIVE_DIR"

  local members=() dir
  for dir in "${CERTBOT_STATE_DIRS[@]}"; do
    [ -e "$STATE_DIR/$dir" ] && members+=("./$dir")
  done

  tar -czf "$WORK/state.tar.gz" -C "$STATE_DIR" "${members[@]}"
  base64 -w0 <"$WORK/state.tar.gz" >"$WORK/payload.b64"
  chmod 600 "$WORK/payload.b64"

  local encoded_bytes
  encoded_bytes="$(wc -c <"$WORK/payload.b64")"
  [ "$encoded_bytes" -le "$MAX_ENCODED_BYTES" ] ||
    die "the certbot state encodes to $encoded_bytes bytes, over the $MAX_ENCODED_BYTES ceiling"

  aws secretsmanager put-secret-value \
    --region "$REGION" --secret-id "$SECRET_ID" \
    --secret-string "file://$WORK/payload.b64" >/dev/null

  log "published the origin certificate to $SECRET_ID ($encoded_bytes bytes encoded)"
}

# --- issue ---------------------------------------------------------------------------------------

# Buy a new certificate from Let's Encrypt. Rare by design, and loud when it happens.
#
# TWO NAMES, AND THE SECOND ONE IS LOAD-BEARING. Let's Encrypt rate-limits duplicate certificates
# per EXACT set of identifiers. The single-name set {node-rpc.dig.net} is the one that was
# exhausted during #2037, so this orders {node-rpc.dig.net, rpc-origin.dig.net} — a distinct set
# with its own budget. rpc-origin.dig.net has no A or AAAA record and needs none, because dns-01
# validates against the hosted zone rather than against a reachable host.
#
# Do NOT "tidy up" the second name. Removing it moves issuance back onto the exhausted set.
#
# --cert-name pins the on-disk path to the primary hostname, so the identifier list can change
# without moving the files the gateway reads.
issue() {
  log "no certificate available to restore; ordering one from Let's Encrypt" \
    "(this consumes a rate-limited issuance)"

  if ! certbot certonly --dns-route53 --non-interactive --agree-tos \
    --register-unsafely-without-email --no-directory-hooks \
    --cert-name "$PEER_HOST" \
    -d "$PEER_HOST" -d "$SAN_HOST"; then
    die "certbot could not obtain a certificate for $PEER_HOST"
  fi

  apply_gateway_access
  save
}

# --- renew ---------------------------------------------------------------------------------------

# The twice-daily timer. certbot decides whether anything is due; this reacts to the answer.
#
# Comparing the fingerprint either side is what keeps the timer cheap. `certbot renew` exits 0
# whether or not it renewed anything, so without this check every run would write a new secret
# version and bounce the gateway twice a day for months with nothing having changed.
renew() {
  local before after
  before="$(certificate_fingerprint)"

  # Checked explicitly rather than left to `set -e`: when a caller invokes this function from an
  # `if`, `set -e` is suspended for the whole body, and a silently-ignored certbot failure would
  # then be read as "nothing was due".
  if ! certbot renew --quiet --dns-route53 --no-directory-hooks; then
    log "certbot renew failed"
    return 1
  fi

  after="$(certificate_fingerprint)"
  if [ "$before" = "$after" ]; then
    log "nothing was due; the stored certificate is still current"
    return 0
  fi

  apply_gateway_access
  save
  # certbot rewriting the file does nothing on its own — the gateway holds the certificate it
  # read at startup until it restarts. `try-restart` is a no-op when the gateway is not running,
  # which is the case during first boot.
  systemctl try-restart rpc-gateway.service
  log "the renewed certificate is now being served"
}

# --- ensure ---------------------------------------------------------------------------------------

# A certificate was restored. Serve it, renewing first if it is near the end of its life.
serve_restored() {
  if certificate_is_fresh; then
    log "the restored certificate is good for more than $RENEW_WITHIN_DAYS more days"
    return 0
  fi

  log "the restored certificate expires within $RENEW_WITHIN_DAYS days; renewing it"
  if renew; then
    return 0
  fi

  # A renewal that fails at boot must not take the origin down while the certificate is still
  # valid. There are up to RENEW_WITHIN_DAYS left and the timer retries twice a day, so a Route53
  # or ACME hiccup costs nothing; refusing to serve would cost everything.
  if certificate_is_valid_now; then
    log "renewal failed, but the certificate is still valid ($(certificate_expiry));" \
      "serving it and leaving the retry to certbot-renew.timer"
    return 0
  fi
  die "the certificate has expired and renewal failed"
}

# Nothing is stored. Prefer a certificate this host already has: publishing one costs nothing,
# ordering one costs a fifth of the weekly budget.
adopt_or_issue() {
  if certificate_is_present && certificate_is_valid_now; then
    log "nothing is stored, but this host already holds a usable certificate; publishing it"
    apply_gateway_access
    save
    return 0
  fi
  issue
}

# The boot path: end up with a serving certificate, contacting Let's Encrypt only when this script
# has positively established there is no other way to get one.
ensure() {
  local outcome
  if restore; then
    outcome="$RESTORE_OK"
  else
    outcome=$?
  fi

  case "$outcome" in
  "$RESTORE_OK") serve_restored ;;
  "$RESTORE_ABSENT") adopt_or_issue ;;
  *)
    # The stored state could not be read, so whether a certificate exists is UNKNOWN. Ordering
    # here would be a guess, and a wrong guess spends one of five weekly issuances — the exact
    # move that caused #2037. Serve what is on disk if it can serve, and otherwise stop.
    if certificate_is_present && certificate_is_valid_now; then
      log "could not read $SECRET_ID; serving the certificate already on this host"
      apply_gateway_access
      return 0
    fi
    die "could not read $SECRET_ID and no usable certificate is on disk;" \
      "refusing to order one against an unknown state"
    ;;
  esac
}

# Is there a certificate the gateway can actually serve? The bootstrap gates on this before
# enabling the gateway, so it must mean "parses and matches", not "the file is non-empty".
check() {
  certificate_is_present && certificate_is_valid_now
}

case "${1:-}" in
ensure) ensure ;;
restore) restore ;;
save) save ;;
renew) renew ;;
check) check ;;
*) die "usage: dig-origin-cert {ensure|restore|save|renew|check}" ;;
esac
