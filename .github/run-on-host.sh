#!/usr/bin/env bash
# Run a script on the node host over SSM, show what it printed, and fail unless it succeeded.
#
#   run-on-host.sh <instance-id> <ssm-parameters-json> [execution-timeout-seconds]
#
# Build the parameters with `jq -Rs`, which keeps the script being sent a normal reviewable file
# instead of an escaped one-liner:
#
#   PARAMS="$(jq -Rs '{commands: [.]}' .github/verify-node.sh)"
#   .github/run-on-host.sh "$IID" "$PARAMS"
#
# WHY SSM AND NOT SSH. There is no key pair and sshd is disabled on the host (user_data.sh.tftpl).
# The gateway port is reachable only from CloudFront's origin ranges, so a runner that COULD curl
# it would mean the security group was wrong — running ON the host is a consequence of the
# boundary being right, not a workaround for it.
#
# The interesting part is the ending. `aws ssm send-command` returns as soon as the command is
# ACCEPTED, so a caller that does not poll to a terminal status learns nothing about whether the
# work succeeded. This polls, prints both streams, and exits non-zero on anything but Success.
set -euo pipefail

readonly IID="${1:?instance id}"
readonly PARAMS="${2:?SSM parameters JSON}"
readonly EXECUTION_TIMEOUT="${3:-900}"

# The instance must be reachable by SSM before anything can be sent to it. Usually instant — this
# only has to cover an agent that is briefly restarting.
for _ in $(seq 1 12); do
  PING="$(aws ssm describe-instance-information \
    --filters "Key=InstanceIds,Values=$IID" \
    --query 'InstanceInformationList[0].PingStatus' --output text 2>/dev/null || true)"
  [ "$PING" = "Online" ] && break
  sleep 10
done
[ "${PING:-}" = "Online" ] || {
  echo "$IID is not reachable over SSM (ping status: ${PING:-unknown})" >&2
  exit 1
}

# executionTimeout bounds the RUN. `send-command --timeout-seconds` bounds only how long the
# command may wait to START, so without this a wedged script sits in InProgress until SSM's
# one-hour default, long past anything the caller is willing to wait for.
FULL_PARAMS="$(jq --arg t "$EXECUTION_TIMEOUT" '. + {executionTimeout: [$t]}' <<<"$PARAMS")"

CMD="$(aws ssm send-command --instance-ids "$IID" \
  --document-name AWS-RunShellScript \
  --parameters "$FULL_PARAMS" \
  --query 'Command.CommandId' --output text)"
echo "SSM command $CMD on $IID"

STATUS=Pending
DEADLINE=$((SECONDS + EXECUTION_TIMEOUT + 60))
while [ "$SECONDS" -lt "$DEADLINE" ]; do
  STATUS="$(aws ssm get-command-invocation --command-id "$CMD" --instance-id "$IID" \
    --query Status --output text 2>/dev/null || echo Pending)"
  case "$STATUS" in
  InProgress | Pending | Delayed) sleep 10 ;;
  *) break ;;
  esac
done

# Both streams, always — the on-host script's own output is the only diagnosis available when
# something goes wrong, and it is far more useful than the status word.
#
# Note SSM truncates each stream to 24 000 characters here; the full output is in the command's
# CloudWatch/S3 destination if one is configured.
echo "--- on-host output ---"
aws ssm get-command-invocation --command-id "$CMD" --instance-id "$IID" \
  --query 'StandardOutputContent' --output text || true
aws ssm get-command-invocation --command-id "$CMD" --instance-id "$IID" \
  --query 'StandardErrorContent' --output text >&2 || true

[ "$STATUS" = "Success" ] || {
  echo "the command on $IID ended $STATUS" >&2
  exit 1
}
echo "--- succeeded on $IID ---"
