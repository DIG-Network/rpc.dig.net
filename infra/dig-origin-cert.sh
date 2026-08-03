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
# WHAT IS STORED, AND WHY IT IS THE WHOLE DIRECTORY. The payload is a gzipped tar of the certbot
# state directory, not just the two PEM files. certbot needs its renewal config, its archive and
# its ACME account to renew; restoring only the PEMs would serve traffic today and then silently
# stop renewing, which fails ~60 days later, far from whatever caused it.
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

# certbot's own renewal threshold. Matching it means a certificate restored inside the window is
# renewed at boot rather than waiting for the timer's next run.
readonly RENEW_WITHIN_DAYS=30

# Secrets Manager accepts 65 536 bytes; stop well short so the failure is a clear message here
# rather than an API error at the worst possible moment. A single certificate encodes to ~8.5 KB,
# so this is roughly seven times the real size.
readonly MAX_ENCODED_BYTES=60000

WORK="$(mktemp -d)"
readonly WORK
chmod 700 "$WORK"
trap 'rm -rf "$WORK"' EXIT

log() {
  printf '%s dig-origin-cert: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2
}

die() {
  log "$*"
  exit 1
}

# --- Reading the certificate on disk -----------------------------------------------------------

certificate_is_present() {
  [ -s "$LIVE_DIR/fullchain.pem" ] && [ -s "$LIVE_DIR/privkey.pem" ]
}

# True while the certificate has more than RENEW_WITHIN_DAYS of life left.
certificate_is_fresh() {
  openssl x509 -in "$LIVE_DIR/cert.pem" -noout \
    -checkend "$((RENEW_WITHIN_DAYS * 86400))" >/dev/null 2>&1
}

# A stable identity for "which certificate is this", used to tell a real renewal from a no-op.
certificate_fingerprint() {
  openssl x509 -in "$LIVE_DIR/cert.pem" -noout -fingerprint -sha256 2>/dev/null || echo absent
}

# --- restore ------------------------------------------------------------------------------------

# Replace the local certbot state with the copy in Secrets Manager.
#
# Every step validates before anything on disk is touched. That ordering is the point: restore
# overwrites the state directory wholesale, so a truncated or wrong-shaped payload that got
# halfway through would leave the host with neither the stored certificate nor the one it was
# already serving — turning a recoverable problem back into the outage.
#
# Returns non-zero for "nothing usable is stored", which is a normal state on a first boot, not
# an error.
restore() {
  if ! aws secretsmanager get-secret-value \
        --region "$REGION" --secret-id "$SECRET_ID" \
        --query SecretString --output text >"$WORK/payload.b64" 2>/dev/null; then
    log "no certificate stored in $SECRET_ID"
    return 1
  fi
  chmod 600 "$WORK/payload.b64"

  if [ ! -s "$WORK/payload.b64" ]; then
    log "the stored certificate is empty"
    return 1
  fi
  if ! base64 -d <"$WORK/payload.b64" >"$WORK/state.tar.gz" 2>/dev/null; then
    log "the stored certificate is not valid base64"
    return 1
  fi

  mkdir -p "$WORK/unpacked"
  if ! tar -xzf "$WORK/state.tar.gz" -C "$WORK/unpacked" 2>/dev/null; then
    log "the stored certificate is not a readable gzipped tar"
    return 1
  fi
  if [ ! -s "$WORK/unpacked/live/$PEER_HOST/fullchain.pem" ] ||
     [ ! -s "$WORK/unpacked/live/$PEER_HOST/privkey.pem" ]; then
    log "the stored archive holds no certificate for $PEER_HOST"
    return 1
  fi

  # Move the old state aside rather than deleting it, so a failure part-way through installing
  # the new one is recoverable instead of terminal.
  local displaced="$STATE_DIR.replaced-$$"
  if [ -d "$STATE_DIR" ] && ! mv "$STATE_DIR" "$displaced"; then
    log "could not set the existing state directory aside"
    return 1
  fi
  if ! mv "$WORK/unpacked" "$STATE_DIR"; then
    [ -d "$displaced" ] && mv "$displaced" "$STATE_DIR"
    log "could not install the restored state directory"
    return 1
  fi
  rm -rf "$displaced"

  log "restored the origin certificate from $SECRET_ID"
}

# --- save ----------------------------------------------------------------------------------------

# Publish the local certbot state so the next instance can restore it.
#
# The payload reaches the API as a file reference, never as an argument: anything on a command
# line is readable by every process on the host through /proc, and this box is deliberately
# internet-facing.
save() {
  certificate_is_present ||
    die "refusing to publish: there is no certificate at $LIVE_DIR"

  tar -czf "$WORK/state.tar.gz" -C "$STATE_DIR" .
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

  certbot certonly --dns-route53 --non-interactive --agree-tos \
    --register-unsafely-without-email \
    --cert-name "$PEER_HOST" \
    -d "$PEER_HOST" -d "$SAN_HOST"

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
  certbot renew --quiet --dns-route53
  after="$(certificate_fingerprint)"

  if [ "$before" = "$after" ]; then
    log "nothing was due; the stored certificate is still current"
    return 0
  fi

  save
  # certbot rewriting the file does nothing on its own — the gateway holds the certificate it
  # read at startup until it restarts. `try-restart` is a no-op when the gateway is not running,
  # which is the case during first boot.
  systemctl try-restart rpc-gateway.service
  log "the renewed certificate is now being served"
}

# --- ensure ---------------------------------------------------------------------------------------

# The boot path: end up with a serving certificate, contacting Let's Encrypt only when there is
# no other way to get one.
ensure() {
  if restore && certificate_is_present; then
    if certificate_is_fresh; then
      log "the restored certificate is good for more than $RENEW_WITHIN_DAYS more days"
      return 0
    fi
    log "the restored certificate expires within $RENEW_WITHIN_DAYS days; renewing it"
    renew
    return 0
  fi

  issue
}

case "${1:-}" in
  ensure)  ensure ;;
  restore) restore ;;
  save)    save ;;
  renew)   renew ;;
  *)       die "usage: dig-origin-cert {ensure|restore|save|renew}" ;;
esac
