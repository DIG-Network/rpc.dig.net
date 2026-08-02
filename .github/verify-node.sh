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
echo "capsules visible: $(find /var/lib/dig-node/cache/modules -name '*.module' 2>/dev/null | wc -l)"

echo "--- the gateway answers ---"
curl -fsS --max-time 5 localhost:8080/health
echo

echo "--- an allowlisted method reaches the node ---"
# Must NOT come back -32601: that would mean the gateway is refusing everything, which would make
# the boundary check below pass for the wrong reason.
ALLOWED="$(curl -fsS --max-time 20 localhost:8080 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"dig.health"}')"
echo "$ALLOWED"
echo "$ALLOWED" | grep -q -- '-32601' && { echo "FAIL: the gateway refused an allowlisted method" >&2; exit 1; }

echo "--- a restricted method does not ---"
for method in control.status cache.clear dig.listInventory sign; do
  OUT="$(curl -fsS --max-time 10 localhost:8080 \
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
for port in 9444 9445; do
  ss -tlnH 2>/dev/null | awk '{print $4}' | grep -q ":$port$" \
    || { echo "FAIL: nothing is listening on $port" >&2; exit 1; }
done
echo "9444 + 9445 listening"

echo "VERIFIED"
