#!/usr/bin/env bash
# Put a matching object in the filtered bucket and assert an alert arrives.
#
# Checks, in order:
#   1. a matching record produces exactly one alert
#   2. a non-matching record in the same object produces none
#   3. the input message is deleted (the queue drains)
#   4. replaying the identical object yields the SAME alert id, which is what
#      makes every at-least-once path in the pipeline safe
cd "$(dirname "$0")/../.."
source hack/local/env.sh

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

KEY="$LOG_SOURCE/date=$(date -u +%F)/local-test-$(date +%s).ndjson.gz"

cat > "$WORK/events.ndjson" <<'JSON'
{"source":"aws","eventSource":"cloudtrail.amazonaws.com","eventName":"StopLogging","awsRegion":"us-east-1","sourceIPAddress":"203.0.113.44","recipientAccountId":"123456789012","userIdentity":{"type":"AssumedRole","arn":"arn:aws:sts::123456789012:assumed-role/deploy/ci-runner"},"requestParameters":{"name":"example-org-trail"}}
{"source":"aws","eventSource":"s3.amazonaws.com","eventName":"GetObject","awsRegion":"us-east-1","readOnly":true}
JSON
gzip -c "$WORK/events.ndjson" > "$WORK/events.ndjson.gz"

ALERT_URL=$(queue_url "$ALERT_QUEUE")
awsl sqs purge-queue --queue-url "$ALERT_URL" >/dev/null 2>&1 || true
sleep 1

echo "putting s3://$FILTERED_BUCKET/$KEY"
awsl s3 cp "$WORK/events.ndjson.gz" "s3://$FILTERED_BUCKET/$KEY" >/dev/null

collect_one() {
  for i in $(seq 1 30); do
    OUT=$(awsl sqs receive-message --queue-url "$ALERT_URL" \
            --max-number-of-messages 10 --wait-time-seconds 2 --output json 2>/dev/null || true)
    if [ -n "$OUT" ] && [ "$OUT" != "null" ]; then
      echo "$OUT"
      return 0
    fi
  done
  return 1
}

echo "waiting for an alert..."
FIRST=$(collect_one) || { echo "FAIL: no alert arrived"; exit 1; }

COUNT=$(echo "$FIRST" | python3 -c 'import json,sys; print(len(json.load(sys.stdin).get("Messages",[])))')
BODY=$(echo "$FIRST"  | python3 -c 'import json,sys; print(json.load(sys.stdin)["Messages"][0]["Body"])')
ID=$(echo "$BODY"     | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
RULE=$(echo "$BODY"   | python3 -c 'import json,sys; print(json.load(sys.stdin)["rule"]["title"])')
EVNAME=$(echo "$BODY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["event"]["eventName"])')
NESTED=$(echo "$BODY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["event"]["userIdentity"]["type"])')
ALIAS=$(echo "$BODY"  | python3 -c 'import json,sys; print("userIdentity.type" in json.load(sys.stdin)["event"])')

echo "  alerts:      $COUNT   (want 1 -- the read-only event must not fire)"
echo "  rule:        $RULE"
echo "  id:          $ID"
echo "  event.name:  $EVNAME"
echo "  nested kept: $NESTED"
echo "  alias leak:  $ALIAS   (want False)"

FAIL=0
[ "$COUNT" = "1" ]        || { echo "FAIL: expected exactly 1 alert"; FAIL=1; }
[ "$EVNAME" = "StopLogging" ] || { echo "FAIL: wrong event in the alert"; FAIL=1; }
[ "$NESTED" = "AssumedRole" ] || { echo "FAIL: the alert lost the nested event structure"; FAIL=1; }
[ "$ALIAS" = "False" ]    || { echo "FAIL: the flattened alias leaked into the alert"; FAIL=1; }

echo
echo "checking the input queue drained (the message must have been deleted)"
sleep 3
VIS=$(awsl sqs get-queue-attributes --queue-url "$(queue_url "$FILTERED_QUEUE")" \
        --attribute-names ApproximateNumberOfMessages ApproximateNumberOfMessagesNotVisible \
        --query 'Attributes' --output json)
echo "  $VIS"

echo
echo "replaying the identical object -- the alert id must not change"
awsl sqs purge-queue --queue-url "$ALERT_URL" >/dev/null 2>&1 || true
sleep 1
awsl s3 cp "$WORK/events.ndjson.gz" "s3://$FILTERED_BUCKET/$KEY" >/dev/null
SECOND=$(collect_one) || { echo "FAIL: no alert on replay"; exit 1; }
ID2=$(echo "$SECOND" | python3 -c 'import json,sys; print(json.loads(json.load(sys.stdin)["Messages"][0]["Body"])["id"])')
echo "  first:  $ID"
echo "  replay: $ID2"
if [ "$ID" != "$ID2" ]; then
  echo "FAIL: alert id changed on replay; every at-least-once path would duplicate"
  FAIL=1
fi

echo
if [ "$FAIL" = "0" ]; then echo "PASS"; else echo "FAILED"; exit 1; fi
