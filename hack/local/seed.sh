#!/usr/bin/env bash
# Create the buckets, queues and notification that mirror the aws-siem
# detection-engine module,
# then upload the repo's rules.
cd "$(dirname "$0")/../.."
source hack/local/env.sh

echo "waiting for localstack..."
for i in $(seq 1 40); do
  if curl -fs "$ENDPOINT/_localstack/health" >/dev/null 2>&1; then break; fi
  sleep 1
done

echo "buckets"
awsl s3api head-bucket --bucket "$FILTERED_BUCKET" 2>/dev/null || awsl s3 mb "s3://$FILTERED_BUCKET" >/dev/null
awsl s3api head-bucket --bucket "$RULES_BUCKET"    2>/dev/null || awsl s3 mb "s3://$RULES_BUCKET"    >/dev/null

echo "queues"
for q in "$FILTERED_QUEUE" "$ALERT_QUEUE"; do
  awsl sqs create-queue --queue-name "$q" >/dev/null
done
FILTERED_URL=$(queue_url "$FILTERED_QUEUE")
FILTERED_ARN=$(awsl sqs get-queue-attributes --queue-url "$FILTERED_URL" \
  --attribute-names QueueArn --query 'Attributes.QueueArn' --output text)

# The prefix filter deliberately has no "=" in its leading segment. S3 matches
# prefix filters against the URL-encoded key, so a filter containing "=" is
# accepted and then never fires -- the same trap documented in
# the aws-siem module and easy to hit.
echo "notification: s3://$FILTERED_BUCKET/$LOG_SOURCE/ -> $FILTERED_QUEUE"
awsl s3api put-bucket-notification-configuration \
  --bucket "$FILTERED_BUCKET" \
  --notification-configuration "{
    \"QueueConfigurations\": [{
      \"Id\": \"$LOG_SOURCE\",
      \"QueueArn\": \"$FILTERED_ARN\",
      \"Events\": [\"s3:ObjectCreated:*\"],
      \"Filter\": {\"Key\": {\"FilterRules\": [{\"Name\": \"prefix\", \"Value\": \"$LOG_SOURCE/\"}]}}
    }]
  }"

echo "rules"
awsl s3 sync rules/ "s3://$RULES_BUCKET/" --exclude '*.tests.yml' --exclude 'README.md' --exclude 'examples/*' --delete >/dev/null
awsl s3 ls "s3://$RULES_BUCKET/$LOG_SOURCE/"

echo
echo "seeded. now run:  make local-run     (in another shell)"
echo "then:             make local-verify"
