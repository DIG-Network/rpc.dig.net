#!/usr/bin/env bash
# Post-deploy verification, run ON the node host via SSM by .github/workflows/deploy.yml.
#
# It lives in the repo rather than inline in the workflow so the acceptance bar is reviewable in a
# diff. Every check below is something that can be false while `terraform apply` is still green.
set -euo pipefail

echo "--- waiting for first boot to finish ---"
cloud-init status --wait >/dev/null 2>&1 || true
for _ in $(seq 1 40); do
  systemctl is-active --quiet rpc-gateway && break
  sleep 10
done

echo "--- the three units are running ---"
systemctl is-active dig-capsules dig-node rpc-gateway

echo "--- capsules come from S3, not from this disk ---"
# `mountpoint` is the check that matters: if the Mountpoint service failed, the directory still
# EXISTS and is simply empty, so a listing alone would look like "no capsules yet" rather than a
# broken storage tier.
mountpoint /var/lib/dig-node/cache/modules
# `.dig` is the canonical capsule suffix. This counted `*.module` — the retired spelling — and so
# reported "capsules visible: 0" against a fully-populated mount, which reads as a broken storage
# tier on every deploy. `.module` stays in the glob only so a node mid-migration is not undercounted
# (dig-node's `migrate_legacy_module_extensions` renames them at bring-up).
CAPSULES="$(find /var/lib/dig-node/cache/modules \( -name '*.dig' -o -name '*.module' \) 2>/dev/null | wc -l)"
echo "capsules visible: $CAPSULES"
# Zero capsules behind a healthy mountpoint means the bucket is unreadable or empty — the node will
# answer /health and then miss every read. That must fail the deploy, not print a zero and pass.
[ "$CAPSULES" -gt 0 ] || { echo "FAIL: the capsule mount is a mountpoint but exposes no capsules" >&2; exit 1; }

echo "--- the gateway answers ---"
# The gateway terminates TLS on 443 (GATEWAY_LISTEN=0.0.0.0:443); it has not served plaintext 8080
# since that cutover, so probing 8080 failed on every healthy deploy and reported the whole run RED
# (dig_ecosystem#2034). A verification step that is always red is worse than none — it trains the
# operator to ignore a genuine failure, and this repo has had one.
#
# `--resolve` pins the real certificate name to the loopback address, so this still validates the
# cert chain the public depends on rather than skipping verification with `-k`. A verify step is
# the right place to catch an expired or misissued cert (see #2037, which took the tier down ~21h).
GATEWAY="https://node-rpc.dig.net"
RESOLVE=(--resolve "node-rpc.dig.net:443:127.0.0.1")
curl -fsS --max-time 5 "${RESOLVE[@]}" "$GATEWAY/health"
echo

echo "--- an allowlisted method reaches the node ---"
# Must NOT come back -32601: that would mean the gateway is refusing everything, which would make
# the boundary check below pass for the wrong reason.
ALLOWED="$(curl -fsS --max-time 20 "${RESOLVE[@]}" "$GATEWAY" \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"dig.health"}')"
echo "$ALLOWED"
echo "$ALLOWED" | grep -q -- '-32601' && { echo "FAIL: the gateway refused an allowlisted method" >&2; exit 1; }

echo "--- a restricted method does not ---"
for method in control.status cache.clear dig.listInventory sign; do
  OUT="$(curl -fsS --max-time 10 "${RESOLVE[@]}" "$GATEWAY" \
    -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\"}")"
  echo "$OUT" | grep -q -- '-32601' || { echo "FAIL: $method was not refused: $OUT" >&2; exit 1; }
done
echo "restricted methods refused"

echo "--- the node's own surface is loopback-only ---"
# 9778 must answer on loopback and must NOT be bound to a routable address.
curl -fsS --max-time 5 localhost:9778/health >/dev/null
if ss -tlnH 2>/dev/null | awk '{print $4}' | grep -Eq '^(0\.0\.0\.0|\[::\]|\*):9778$'; then
  echo "FAIL: 9778 is bound to a wildcard address" >&2
  exit 1
fi
echo "9778 is loopback-only"

echo "--- peer ports are listening ---"
# The peer network comes up AFTER the HTTP surface, not with it: dig-node dials the relay, runs
# STUN reflexive discovery, joins the DHT, and only then binds 9444. Measured at ~36 s past the
# gateway answering. Checking once, immediately after /health, fails on a node that is perfectly
# healthy and merely still starting.
for port in 9444 9445; do
  for _ in $(seq 1 30); do
    ss -tlnH 2>/dev/null | awk '{print $4}' | grep -q ":$port\$" && break
    sleep 5
  done
  ss -tlnH 2>/dev/null | awk '{print $4}' | grep -q ":$port\$" \
    || { echo "FAIL: nothing is listening on $port after 150s" >&2;
         journalctl -u dig-node -n 40 --no-pager >&2; exit 1; }
done
echo "9444 + 9445 listening"

echo "--- this node is actually peered, not just listening ---"
# A bound socket proves nothing about reachability. Require at least one established peer
# connection, which is the difference between "a node" and "a node on the network".
for _ in $(seq 1 24); do
  PEERED="$(journalctl -u dig-node --no-pager 2>/dev/null | grep -c 'peer connection established' || true)"
  [ "${PEERED:-0}" -gt 0 ] && break
  sleep 5
done
[ "${PEERED:-0}" -gt 0 ] || { echo "FAIL: no peer connection was ever established" >&2; exit 1; }
echo "peer connections established: $PEERED"

echo "--- nothing else is listening on a routable address ---"
# The whole point of the peer ports being open is that they are the ONLY thing open. Enumerate
# every non-loopback listener and assert the set is exactly what this service intends.
UNEXPECTED="$(ss -tlnH 2>/dev/null | awk '{print $4}' \
  | grep -vE '^(127\.0\.0\.1|\[::1\]):' \
  | grep -vE ':(9444|9445|443)$' || true)"
if [ -n "$UNEXPECTED" ]; then
  echo "FAIL: unexpected listener(s) on a routable address:" >&2
  echo "$UNEXPECTED" >&2
  exit 1
fi
# 443 replaces 8080 here for the same reason as above. Note this assertion was NOT protecting
# anything while it named 8080: the step aborted at the /health probe several checks earlier, so
# the boundary check never ran on any deploy since the TLS cutover.
echo "routable listeners are exactly 9444, 9445, 443"

echo "VERIFIED"
