#!/usr/bin/env bash
# Run the engine image against localstack.
#
# The engine runs as a container on the compose network, so the endpoint it
# sees is http://localstack:4566 while the seed/verify scripts on the host use
# http://localhost:4566. Queue URLs returned by localstack carry the host-side
# hostname, so they are rewritten to the in-network one; the SDK sends every
# request to ENGINE_SQS_ENDPOINT_URL anyway and localstack resolves the queue
# from the URL path.
cd "$(dirname "$0")/../.."
source hack/local/env.sh

IMAGE=${IMAGE:-detection-engine:dev}
NETWORK=${NETWORK:-detection-engine-local_default}
INNER_ENDPOINT=${INNER_ENDPOINT:-http://localstack:4566}

rewrite() { sed -E "s#https?://[^/]+#${INNER_ENDPOINT}#"; }

QUEUE_URL=$(queue_url "$FILTERED_QUEUE" | rewrite)
ALERT_URL=$(queue_url "$ALERT_QUEUE" | rewrite)

echo "running $IMAGE on network $NETWORK (source=$LOG_SOURCE)"
exec docker run --rm --name detection-engine-local \
  --network "$NETWORK" -p "${ENGINE_METRICS_PORT:-9090}:9090" \
  -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_REGION \
  -e ENGINE_LOG_SOURCE="$LOG_SOURCE" \
  -e ENGINE_QUEUE_URL="$QUEUE_URL" \
  -e ENGINE_ALERT_QUEUE_URL="$ALERT_URL" \
  -e ENGINE_RULES_DIR= \
  -e ENGINE_RULES_BUCKET="$RULES_BUCKET" \
  -e ENGINE_S3_ENDPOINT_URL="$INNER_ENDPOINT" \
  -e ENGINE_SQS_ENDPOINT_URL="$INNER_ENDPOINT" \
  -e ENGINE_LOG_LEVEL="${ENGINE_LOG_LEVEL:-info}" \
  -e ENGINE_METRICS_ADDR=:9090 \
  -e ENGINE_VISIBILITY_TIMEOUT=60s \
  -e ENGINE_VISIBILITY_HEARTBEAT=20s \
  "$IMAGE"
