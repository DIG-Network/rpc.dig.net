#!/usr/bin/env bash
# In-place dig-node update, run ON the node host via SSM by .github/workflows/auto-update-node.yml.
#
# It lives in the repo rather than inline in the workflow for the same reason
# `.github/verify-node.sh` does: this runs as root on the machine that serves the public read tier,
# so it should be reviewable in a diff. Its ordering is driven against fakes in
# `tests/update_node.rs`, because "verifies before it installs" is a claim, and a claim about a
# shell script inside a workflow is otherwise unfalsifiable.
#
# WHY IN PLACE, AND NOT `terraform apply`
#
# The node version is baked into user_data and `user_data_replace_on_change = true`, so an apply
# REPLACES the instance. That is right for a deliberate deploy and wrong for a nightly one: a
# replacement re-runs `dnf -y update` (an unpinned input) and re-restores the origin certificate,
# and if that restore ever fails it falls through to ordering a new one — five per week, and
# exhausting them took the read tier down for ~21 hours (dig_ecosystem#2037). A scheduled,
# unattended replacement puts that failure on a timer. Swapping one binary does not.
#
# Terraform stays the only writer of AWS resources; this script writes one file and restarts two
# units. The workflow bumps the DIG_NODE_* repo variables in the same run, so the pinned bootstrap
# and the running host never disagree and the next real apply reinstalls what is already running
# rather than reverting it (dig_ecosystem#2034).
#
# THE ORDERING IS THE SAFETY PROPERTY
#
# Download → verify the checksum → prove the file executes → keep the old binary → swap → restart →
# prove it serves → roll back if it does not. Nothing touches the running node until the bytes are
# proven, and the binary that was replaced stays on disk as `dig-node.rollback` afterwards.
set -euo pipefail

# What to install. The workflow validates the shape of all three before sending them.
readonly NEW_URL="${NEW_URL:?the artifact URL must be set}"
readonly NEW_SHA="${NEW_SHA:?the artifact sha256 must be set}"
readonly NEW_VERSION="${NEW_VERSION:?the release tag must be set}"

# Permit installing an older release. Off by default: automatic selection is newest-wins, so a
# downgrade only ever arrives from a hand-run or a deliberate rollback.
readonly ALLOW_DOWNGRADE="${ALLOW_DOWNGRADE:-0}"

# Overridable so the test suite can drive this script against a sandbox instead of the real host.
# Production never sets any of them.
readonly BIN_DIR="${DIG_NODE_UPDATE_BIN_DIR:-/usr/local/bin}"
readonly STATE_DIR="${DIG_NODE_UPDATE_STATE_DIR:-/var/lib/dig-node}"
readonly CERT_ENV="${DIG_NODE_UPDATE_CERT_ENV:-/etc/dig-origin-cert.env}"
# Ownership imposed on the installed binary. Overridable because the tests are not root and
# cannot chown to it.
readonly INSTALL_OWNER="${DIG_NODE_UPDATE_OWNER:-root:root}"
# Seconds to wait for the stack to come back. Overridable only so the tests do not spend two
# minutes sleeping on the rollback path.
readonly HEALTH_TIMEOUT_SECONDS="${DIG_NODE_UPDATE_HEALTH_TIMEOUT:-120}"

readonly BIN="$BIN_DIR/dig-node"
readonly CANDIDATE="$BIN.candidate"
readonly ROLLBACK="$BIN.rollback"
readonly STAMP="$STATE_DIR/DIG_NODE_VERSION"

# The certificate's hostname is the name the gateway serves under. Read from the file that already
# carries it rather than hardcoding a second copy that can drift from terraform.
#
# `|| true` is load-bearing. Under `set -e` the exit status of an assignment IS the status of its
# command substitution, so if that file is missing the shell exits here — before the first `echo`,
# with no output at all and an exit code that looks like a bash syntax error. The fallback below
# only gets to be a fallback if reading is allowed to fail.
ORIGIN_HOST="$(sed -n 's/^DIG_ORIGIN_CERT_HOST=//p' "$CERT_ENV" 2>/dev/null | head -1 || true)"
readonly ORIGIN_HOST="${ORIGIN_HOST:-node-rpc.dig.net}"

CURRENT="$(cat "$STAMP" 2>/dev/null || echo v0.0.0)"
readonly CURRENT

echo "installed=$CURRENT requested=$NEW_VERSION origin_host=$ORIGIN_HOST"
echo "running binary reports: $("$BIN" --version 2>&1 | head -1 || echo '(could not be queried)')"

if [ "$CURRENT" = "$NEW_VERSION" ]; then
  echo "already on $NEW_VERSION; nothing to do"
  exit 0
fi

# Refuse to go backwards unless that is what was asked for. The workflow already picks
# newest-wins, so this is the guard that survives a hand-run with the wrong tag.
if [ "$ALLOW_DOWNGRADE" != "1" ]; then
  oldest="$(printf '%s\n%s\n' "$CURRENT" "$NEW_VERSION" | sort -V | head -1)"
  if [ "$oldest" = "$NEW_VERSION" ]; then
    echo "REFUSING: $NEW_VERSION is older than the installed $CURRENT" >&2
    echo "Re-run with the workflow's 'version' input if this is a deliberate rollback." >&2
    exit 1
  fi
fi

TMP=""
cleanup() { rm -f "$CANDIDATE" ${TMP:+"$TMP"}; }
trap cleanup EXIT

# --- 1. Fetch and verify. The running node is untouched throughout. -----------------------------
TMP="$(mktemp)"
curl -fsSL --retry 3 --retry-connrefused --retry-delay 2 -o "$TMP" "$NEW_URL"
echo "$NEW_SHA  $TMP" | sha256sum -c -

# --- 2. Prove it runs on this machine before it becomes the node --------------------------------
# A checksum proves only that the bytes are the ones the runner fetched. It says nothing about
# whether they are an aarch64 executable this host's glibc can load, and a wrong-architecture
# binary that passes its checksum would otherwise be discovered by systemd, after the swap.
install -m 0755 -o "${INSTALL_OWNER%%:*}" -g "${INSTALL_OWNER##*:}" "$TMP" "$CANDIDATE"
"$CANDIDATE" --version

# --- 3. Keep what is being replaced -------------------------------------------------------------
# On disk, beside the binary, so a rollback is a rename and needs no network. Deliberately left
# behind after a successful update — runbooks/deploy.md documents the one-line manual rollback.
cp -a "$BIN" "$ROLLBACK"

# --- 4. Swap and restart ------------------------------------------------------------------------
# `mv` within a filesystem is atomic, and safe against a running process: the executing node holds
# its own inode, so nothing changes for it until it restarts.
mv -f "$CANDIDATE" "$BIN"

restart_stack() {
  systemctl restart dig-node.service
  # rpc-gateway declares `Requires=dig-node.service`, so systemd may take it down alongside the
  # node. `start` is a no-op when it is already up and repairs it when it is not — without it, a
  # successful node update can leave the public read tier stopped.
  systemctl start rpc-gateway.service
}
restart_stack

# --- 5. Prove it serves, or put the old one back ------------------------------------------------
serving_version() {
  curl -fsS --max-time 10 localhost:9778 \
    -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"dig.health"}' 2>/dev/null |
    grep -o '"version":"[^"]*"' | head -1 | cut -d'"' -f4
}

gateway_answers() {
  curl -fsS --max-time 5 --resolve "$ORIGIN_HOST:443:127.0.0.1" \
    "https://$ORIGIN_HOST/health" >/dev/null 2>&1
}

# Healthy means all three: the node answers, it answers AS the version just installed, and the
# gateway in front of it answers over real TLS. Checking only that the node process is up would
# call an update successful while the public tier was down.
await_healthy() {
  local want="$1" saw="" waited=0
  while [ "$waited" -lt "$HEALTH_TIMEOUT_SECONDS" ]; do
    saw="$(serving_version || true)"
    if [ "$saw" = "$want" ] && gateway_answers; then
      echo "serving $saw through the gateway"
      return 0
    fi
    sleep 3
    waited=$((waited + 3))
  done
  echo "node reported version '${saw:-<no answer>}', wanted '$want'" >&2
  return 1
}

if await_healthy "${NEW_VERSION#v}"; then
  # Recorded only once the new binary is PROVEN to serve, and this ordering is deliberate.
  #
  # Written before the health wait, an interruption in between — an SSM execution timeout, a
  # SIGTERM, the box rebooting — would leave a stamp naming a release nothing verified, while the
  # workflow never reached the step that moves the repository variables. New binary, new stamp,
  # old pin, no rollback: exactly the divergence SPEC §7.2 forbids, arrived at sideways.
  #
  # Written here, the same interruption leaves the stamp naming the OLD release, which is
  # self-healing: the next run sees a version behind, installs again, and converges. Stale-old
  # costs one redundant install. Stale-new is a silent lie that a re-run would no-op on.
  echo "$NEW_VERSION" >"$STAMP"
  echo "UPDATED $CURRENT -> $NEW_VERSION"
  exit 0
fi

echo "FAILED to come up on $NEW_VERSION; rolling back to $CURRENT" >&2
journalctl -u dig-node -n 60 --no-pager >&2 || true

mv -f "$ROLLBACK" "$BIN"
# Idempotent now that the stamp only moves on success — it already says "$CURRENT". Kept as a
# positive assertion of what is installed rather than a reliance on nothing else having touched it.
echo "$CURRENT" >"$STAMP"
restart_stack

if await_healthy "${CURRENT#v}"; then
  echo "ROLLED BACK to $CURRENT and serving; $NEW_VERSION was NOT installed" >&2
else
  echo "CRITICAL: rollback to $CURRENT did not restore service. rpc.dig.net needs a human." >&2
fi
exit 1
