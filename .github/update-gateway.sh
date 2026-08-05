#!/usr/bin/env bash
# In-place rpc-gateway update, run ON the node host via SSM by .github/workflows/deploy.yml.
#
# It lives in the repo rather than inline in the workflow for the same reason `.github/update-node.sh`
# and `.github/verify-node.sh` do: this runs as root on the machine that serves the public read tier,
# so it must be reviewable in a diff. Its ordering is driven against fakes in `tests/update_gateway.rs`,
# because "verifies before it installs" and "rolls back a gateway that does not serve" are claims, and
# a claim about a shell script inside a workflow is otherwise unfalsifiable.
#
# WHY IN PLACE, AND NOT A TERRAFORM REPLACEMENT
#
# The gateway binary's SHA is templated into user_data, and a replace-on-user_data-change deploy
# TerminateInstances + RunInstances'd the box on every release: ~2.5 min of public outage, plus the
# certificate-restore path that took the tier down ~21h when it fell through to a fresh issuance
# (dig_ecosystem#2034 / #2037). Terraform now leaves the instance still (infra/node.tf:
# `user_data_replace_on_change = false` + `ignore_changes = [user_data_base64]`), and this script
# swaps ONE checksum-verified binary and restarts one unit instead. Terraform stays the only writer
# of AWS resources; this writes one file on a host it already owns.
#
# THE ORDERING IS THE SAFETY PROPERTY
#
# Skip if already installed → download → verify the checksum → prove the file is an executable this
# host can load → keep the old binary → swap → restart → prove the gateway serves over real TLS →
# roll back if it does not. Nothing touches the running gateway until the bytes are proven, and the
# binary that was replaced stays on disk as `rpc-gateway.rollback` afterwards.
set -euo pipefail

# What to install. deploy.yml computes the SHA from the exact bytes it just published and validates
# the shape of both before sending them.
readonly NEW_URL="${NEW_URL:?the artifact URL must be set}"
readonly NEW_SHA="${NEW_SHA:?the artifact sha256 must be set}"

# Overridable so the test suite can drive this script against a sandbox instead of the real host.
# Production never sets any of them.
readonly BIN_DIR="${GATEWAY_UPDATE_BIN_DIR:-/usr/local/bin}"
readonly CERT_ENV="${GATEWAY_UPDATE_CERT_ENV:-/etc/dig-origin-cert.env}"
# Ownership imposed on the installed binary. Overridable because the tests are not root.
readonly INSTALL_OWNER="${GATEWAY_UPDATE_OWNER:-root:root}"
# Seconds to wait for the unit to appear (a fresh boot is still installing) and to come back after a
# restart. Overridable only so the tests do not spend minutes sleeping.
readonly UNIT_TIMEOUT_SECONDS="${GATEWAY_UPDATE_UNIT_TIMEOUT:-600}"
readonly HEALTH_TIMEOUT_SECONDS="${GATEWAY_UPDATE_HEALTH_TIMEOUT:-60}"
# The command that classifies a downloaded file's architecture. Overridable so the tests can model a
# wrong-arch build; production always uses the real `file`.
readonly FILE_CMD="${GATEWAY_UPDATE_FILE:-file}"

readonly UNIT="rpc-gateway.service"
readonly BIN="$BIN_DIR/rpc-gateway"
readonly CANDIDATE="$BIN.candidate"
readonly ROLLBACK="$BIN.rollback"

# The certificate's hostname is the name the gateway serves under, and the port it binds is in the
# unit's own environment. Read both from where they already live rather than hardcoding a second copy
# that can drift from terraform. `|| true` is load-bearing under `set -e`: the exit status of an
# assignment IS the status of its command substitution, so a missing file would otherwise exit the
# shell here, before the first echo, with a code that looks like a bash syntax error.
ORIGIN_HOST="$(sed -n 's/^DIG_ORIGIN_CERT_HOST=//p' "$CERT_ENV" 2>/dev/null | head -1 || true)"
readonly ORIGIN_HOST="${ORIGIN_HOST:-node-rpc.dig.net}"

gateway_port() {
  local listen
  listen="$(systemctl show "$UNIT" --property=Environment --value 2>/dev/null \
    | tr ' ' '\n' | sed -n 's/^GATEWAY_LISTEN=//p' | head -1)"
  local port="${listen##*:}"
  [[ "$port" =~ ^[0-9]+$ ]] && { echo "$port"; return 0; }
  echo 443
}

# Wait for the unit to be active. On an existing host this is instant; on a FRESH instance cloud-init
# is still installing the pinned gateway, and this covers that window so the swap never races it.
echo "waiting for $UNIT to be active (up to ${UNIT_TIMEOUT_SECONDS}s)"
waited=0
while ! systemctl is-active --quiet "$UNIT"; do
  [ "$waited" -lt "$UNIT_TIMEOUT_SECONDS" ] || { echo "FAIL: $UNIT never became active" >&2; exit 1; }
  sleep 5
  waited=$((waited + 5))
done

# Idempotent, and it is what makes a fresh instance a no-op: user_data already installed exactly
# these bytes at boot, so there is nothing to swap and no reason to bounce the gateway.
if [ -f "$BIN" ]; then
  CURRENT_SHA="$(sha256sum "$BIN" | cut -d' ' -f1)"
  if [ "$CURRENT_SHA" = "$NEW_SHA" ]; then
    echo "the installed gateway already matches $NEW_SHA; nothing to do"
    exit 0
  fi
fi

TMP=""
cleanup() { rm -f "$CANDIDATE" ${TMP:+"$TMP"}; }
trap cleanup EXIT

# --- 1. Fetch and verify. The running gateway is untouched throughout. --------------------------
TMP="$(mktemp)"
curl -fsSL --retry 3 --retry-connrefused --retry-delay 2 -o "$TMP" "$NEW_URL"
echo "$NEW_SHA  $TMP" | sha256sum -c -

# --- 2. Prove it is an executable this host can load --------------------------------------------
# A checksum proves only that the bytes are the ones the runner fetched. A wrong-architecture build
# (this host is Graviton/aarch64) or a non-executable that slipped into the asset slot has a valid
# checksum and would otherwise be discovered by systemd, after the swap, as a crash loop in front of
# the public. Classify before installing.
KIND="$("$FILE_CMD" -b "$TMP")"
echo "candidate kind: $KIND"
case "$KIND" in
  *"ELF 64-bit LSB"*"ARM aarch64"*) ;;
  *) echo "FAIL: $NEW_URL is not an aarch64 ELF executable ($KIND)" >&2; exit 1 ;;
esac
install -m 0755 -o "${INSTALL_OWNER%%:*}" -g "${INSTALL_OWNER##*:}" "$TMP" "$CANDIDATE"

# --- 3. Keep what is being replaced -------------------------------------------------------------
# On disk, beside the binary, so a rollback is a rename and needs no network. Deliberately left
# behind after a successful update — runbooks/deploy.md documents the one-line manual rollback.
cp -a "$BIN" "$ROLLBACK"

# --- 4. Swap and restart ------------------------------------------------------------------------
# `mv` within a filesystem is atomic and safe against a running process: the executing gateway holds
# its own inode, so nothing changes for it until it restarts.
mv -f "$CANDIDATE" "$BIN"
systemctl restart "$UNIT"

# --- 5. Prove it serves, or put the old one back ------------------------------------------------
# Judge success on what is SERVED, not on what was installed. The gateway terminates TLS itself, so
# `--resolve` pins the real certificate name to loopback at the derived port and validates the chain
# the public depends on rather than skipping it with `-k`.
gateway_answers() {
  local port
  port="$(gateway_port)"
  curl -fsS --max-time 5 --resolve "$ORIGIN_HOST:$port:127.0.0.1" \
    "https://$ORIGIN_HOST:$port/health" >/dev/null 2>&1
}

await_serving() {
  local waited=0
  while [ "$waited" -lt "$HEALTH_TIMEOUT_SECONDS" ]; do
    gateway_answers && { echo "the gateway is serving over TLS"; return 0; }
    sleep 3
    waited=$((waited + 3))
  done
  return 1
}

if await_serving; then
  echo "INSTALLED gateway $NEW_SHA and it is serving"
  exit 0
fi

echo "FAILED to serve on the new gateway; rolling back" >&2
journalctl -u "$UNIT" -n 60 --no-pager >&2 || true

mv -f "$ROLLBACK" "$BIN"
systemctl restart "$UNIT"

if await_serving; then
  echo "ROLLED BACK the gateway and it is serving; the new binary was NOT kept" >&2
else
  echo "CRITICAL: rollback did not restore the read tier. rpc.dig.net needs a human." >&2
fi
exit 1
