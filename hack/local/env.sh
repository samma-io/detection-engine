# Shared settings for the local end-to-end scripts.
#
# The credentials are localstack's dummies; it accepts anything non-empty.
set -euo pipefail

export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_REGION=us-east-1
export AWS_DEFAULT_REGION=us-east-1

LOCALSTACK_PORT=${LOCALSTACK_PORT:-4566}
ENDPOINT=${ENDPOINT:-http://localhost:${LOCALSTACK_PORT}}
FILTERED_BUCKET=${FILTERED_BUCKET:-filtered-000000000000-us-east-1}
RULES_BUCKET=${RULES_BUCKET:-detection-rules-000000000000-us-east-1}
LOG_SOURCE=${LOG_SOURCE:-aws}
FILTERED_QUEUE=${FILTERED_QUEUE:-filtered-${LOG_SOURCE}-000000000000-us-east-1}
ALERT_QUEUE=${ALERT_QUEUE:-detections-alerts-000000000000-us-east-1}

awsl() { aws --endpoint-url "$ENDPOINT" "$@"; }

queue_url() { awsl sqs get-queue-url --queue-name "$1" --query QueueUrl --output text; }
