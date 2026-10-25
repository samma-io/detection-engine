# detection-engine

A stateless [Sigma](https://github.com/SigmaHQ/sigma) rule engine for the
[samma-io/aws-siem](https://github.com/samma-io/aws-siem) stack. It drains one
per-lane SQS queue of S3 `ObjectCreated` notifications, evaluates every record
in each object against a Sigma ruleset, and publishes matches to one shared
alert queue.

```
filtered-<bucket>                 filtered-aws      --> detection-engine (aws)      --+
  aws/date=YYYY-MM-DD/...   -S3-> filtered-github   --> detection-engine (github)   --+--> detections-alerts
  github/date=.../...      notify filtered-gcp      --> detection-engine (gcp)      --+       (one queue)
  gcp/date=.../...                ...one queue and one engine service per lane...  --+
                                                                                        |
                                  /rules/<lane>/*.yml (image)  -- read once at start    v
                                                                            alert-destination
```

Status: **pre-alpha**. The engine and rules come from a production deployment;
the open-source packaging (this repository, the aws-siem Terraform) is under
construction. There are no releases: images are built from source and pushed to
your own registry (see [Artifacts](#artifacts)).

## Where it sits in the flow

1. [`samma-io/vector`](https://github.com/samma-io/vector) parses raw logs and
   writes gzipped NDJSON to the *filtered* bucket under `<lane>/date=%F/...`,
   one JSON object per line. Records are vendor-native -- CloudTrail fields for
   `aws`, GitHub audit fields for `github` -- plus a `source` field equal to the
   lane name.
2. An S3 notification per lane prefix feeds a per-lane SQS queue.
3. **This service**, one ECS task set per lane, reads that queue, loads
   `<lane>/` from the rules tree baked into the image (or from the rules
   bucket, when the installation ships its own rules) at start, and evaluates.
4. Alerts (`detection.alert.v1`) land on one shared queue, consumed by
   [`samma-io/alert-destination`](https://github.com/samma-io/alert-destination).

One image serves every lane. `ENGINE_LOG_SOURCE` selects the rules prefix and
the key prefix the engine will accept; the queue URLs come from the
environment. All infrastructure lives in aws-siem (`terraform/modules/detection-engine`).

### The key-prefix contract

`internal/source/registry.go` couples three things on the **lane name**:

| | Value |
|---|---|
| filtered bucket key prefix | `<lane>/` (the S3 notification filters on exactly this) |
| rules prefix (dir or bucket) | `<ENGINE_RULES_PREFIX><lane>/` |
| `source` field on every record | `<lane>` |

The engine asserts the prefix on every incoming key and refuses an object from
another lane rather than evaluating the wrong rules against it. The lane list
and layout are specified in aws-siem:
[`docs/contracts/filtered-object-layout.md`](https://github.com/samma-io/aws-siem/blob/main/docs/contracts/filtered-object-layout.md),
[`docs/contracts/lane-names.md`](https://github.com/samma-io/aws-siem/blob/main/docs/contracts/lane-names.md).
Current lanes: `alb`, `aws`, `cloudflare`, `dns`, `gcp`, `github`, `onepassword`, `slack`, `workspace`.
Two more lanes, `k8s` (Kubernetes audit events) and `scanner` (Samma scanner
findings), exist only on the NATS transport, on `samma.logs.k8s` and
`samma.logs.scanner`; see
[`docs/contracts/nats-transport.md`](https://github.com/samma-io/aws-siem/blob/main/docs/contracts/nats-transport.md).

## Artifacts

One artifact: the image, `ghcr.io/samma-io/detection-engine:<tag>`
(linux/amd64). Nothing is released or published by CI; we build and push it
ourselves, and the tag is whatever the builder passes -- by convention the
repo's short git sha, with no `v` prefix:

```bash
make image push                                   # ghcr.io/samma-io/detection-engine:$(git rev-parse --short HEAD)
make image push IMAGE=ghcr.io/acme/detection-engine TAG=3c0118b
```

aws-siem's `hack/build-images.sh` does exactly this for every service repo.

**Rules ship in one of two ways:**

- **Baked into the image** (the default). The `rules/` tree, without the
  `.tests.yml` sidecars and `examples/`, is copied to `/rules` at build time
  and `ENGINE_RULES_DIR=/rules` is the image default. A rule change is a new
  image.
- **Uploaded from a `rules_dir`.** The aws-siem detection-engine module takes
  a `rules_dir`, uploads it to the rules bucket and sets `ENGINE_RULES_BUCKET`
  (with `ENGINE_RULES_DIR=` empty). The engine reads it at container start, so
  a rule change is an apply plus a task restart, with no rebuild. The directory
  must hold only `<lane>/sigma-config.yml` and `<lane>/*.yml` rules: a
  `.tests.yml` sidecar in it is loaded as a rule and fails the start.

## Run standalone

Everything runs in containers; no local Go toolchain is needed.

```bash
make local-up      # localstack 3.8 with s3 + sqs
make local-seed    # buckets, queues, the lane notification, upload rules/ (needs the aws CLI)
make local-run     # build the image and run it on the compose network
make local-verify  # in another shell: put a matching object, assert one alert, replay for id stability
make local-down
```

`local-verify` checks four things: a matching record produces exactly one
alert, a non-matching record in the same object produces none, the input
message is deleted, and replaying the identical object yields the **same alert
id** -- which is what makes every at-least-once path in the pipeline safe.
`LOG_SOURCE=github make local-seed local-run` exercises another lane, and
`LOCALSTACK_PORT=4599` (exported before every step) moves localstack off 4566
when that port is taken.

The same image runs anywhere with the variables below. The image carries the
`rules/` tree at `/rules` (without `examples/` and the `.tests.yml` sidecars)
and defaults to `ENGINE_RULES_DIR=/rules`, so no rules bucket is needed:

```bash
docker run --rm -p 9090:9090 \
  -e ENGINE_LOG_SOURCE=aws \
  -e ENGINE_QUEUE_URL=https://sqs.eu-west-1.amazonaws.com/123456789012/filtered-aws \
  -e ENGINE_ALERT_QUEUE_URL=https://sqs.eu-west-1.amazonaws.com/123456789012/detections-alerts \
  -e AWS_REGION=eu-west-1 \
  ghcr.io/samma-io/detection-engine:<tag>
```

To run an installation's own rules instead, point the task at a bucket and
unset the directory -- the engine refuses to start with both, rather than
guess which ruleset was meant:

```bash
docker run --rm -p 9090:9090 \
  -e ENGINE_LOG_SOURCE=aws \
  -e ENGINE_QUEUE_URL=... -e ENGINE_ALERT_QUEUE_URL=... -e AWS_REGION=eu-west-1 \
  -e ENGINE_RULES_DIR= \
  -e ENGINE_RULES_BUCKET=my-siem-rules \
  ghcr.io/samma-io/detection-engine:<tag>
```

The localstack flow above seeds the bucket and runs with `ENGINE_RULES_BUCKET`,
so it exercises the override path; `ls /rules/aws` inside the image shows what
the default path loads.

## Configuration

Wiring is required and has no default: there is no safe guess for "which queue
to read", and a service pointed at nothing looks healthy on every dashboard.
Tuning knobs default, because a required knob is a knob that gets copy-pasted.
Every problem is reported in one error at start.

| Var | Required | Default | Purpose |
|---|---|---|---|
| `ENGINE_LOG_SOURCE` | yes | -- | lane: `alb`\|`aws`\|`cloudflare`\|`dns`\|`gcp`\|`github`\|`onepassword`\|`slack`\|`workspace`, or on NATS only `k8s`\|`scanner` |
| `ENGINE_TRANSPORT` | no | `sqs` | `sqs` (AWS: S3 notifications) or `nats` (Kubernetes: records on JetStream) |
| `ENGINE_QUEUE_URL` | sqs | -- | the lane's `filtered-<lane>` queue |
| `ENGINE_ALERT_QUEUE_URL` | sqs | -- | the shared `detections-alerts` queue |
| `ENGINE_NATS_URL` | nats | -- | e.g. `nats://nats.samma.svc:4222` |
| `ENGINE_NATS_STREAM` | no | `SIEM_LOGS` | stream holding `samma.logs.>` |
| `ENGINE_NATS_CONSUMER` | no | `detection-engine-<lane>` | durable pull consumer; must exist and filter `ENGINE_NATS_SUBJECT` |
| `ENGINE_NATS_SUBJECT` | no | `samma.logs.<lane>` | checked against the consumer's filter at start |
| `ENGINE_ALERT_SUBJECT` | no | `samma.alerts.<lane>` | alerts are published here with `Nats-Msg-Id` = alert id |
| `ENGINE_RULES_DIR` | one of | `/rules` (image) | load rules from this directory; the image bakes `rules/` in here |
| `ENGINE_RULES_BUCKET` | one of | -- | load rules from this S3 bucket instead; set `ENGINE_RULES_DIR=` (empty) alongside it |
| `AWS_REGION` | sqs, or with a rules bucket | -- | SDK region |
| `ENGINE_RULES_PREFIX` | no | `""` | prepended to `<lane>/` under the dir or bucket; a trailing `/` is added if missing |
| `ENGINE_WORKERS` | no | `4` | concurrent workers, each with one in-flight message |
| `ENGINE_MAX_OBJECT_BYTES` | no | `268435456` | refuse objects above this (256 MiB) |
| `ENGINE_MAX_OBJECT_DURATION` | no | `45m` | per-object deadline |
| `ENGINE_MAX_DECODE_ERROR_RATIO` | no | `0.01` | above this share of bad lines, fail the object |
| `ENGINE_MAX_ALERTS_PER_OBJECT` | no | `10000` | circuit breaker on an over-broad rule |
| `ENGINE_VISIBILITY_TIMEOUT` | no | `300s` | must match the queue's setting |
| `ENGINE_VISIBILITY_HEARTBEAT` | no | `100s` | must be shorter than the timeout |
| `ENGINE_METRICS_ADDR` | no | `:9090` | admin listener |
| `ENGINE_LOG_LEVEL` | no | `info` | `debug`\|`info`\|`warn`\|`error` |
| `ENGINE_S3_ENDPOINT_URL` | no | `""` | localstack only; enables path-style S3 |
| `ENGINE_SQS_ENDPOINT_URL` | no | `""` | localstack only |

Exactly one of `ENGINE_RULES_DIR` and `ENGINE_RULES_BUCKET` must be set; both
or neither is a startup error.

With `ENGINE_TRANSPORT=nats` each message body is NDJSON (gzipped or not) of
filtered records, the same lines a filtered object holds. Provenance is
`bucket = nats:<stream>`, `key = <subject>/<stream sequence>`, so a redelivery
yields the same alert ids. The consumer's `AckWait` plays the role of the
visibility timeout and must match `ENGINE_VISIBILITY_TIMEOUT`; `MaxDeliver`
plays the role of the DLQ. See aws-siem `docs/contracts/detection-alert-v1.md`. Standard AWS SDK credential resolution applies
(task role, env, profile).

## Endpoints

`:9090/healthz` liveness (always 200) - `/readyz` readiness (true once rules
load) - `/metrics` Prometheus - `/rules` the loaded ruleset, which answers "is
this task running what is in git?" without a redeploy.

## Rules

```
rules/<lane>/sigma-config.yml       sigma-go Config: logsource + field mappings for the lane
rules/<lane>/<rule>.yml             a Sigma rule
rules/<lane>/<rule>.tests.yml       REQUIRED: cases proving the rule fires (and does not)
rules/examples/org-specific/        rules that need your account ids / domain / vault uuids
docs/RULES.md                       generated catalogue: every rule, its level, condition, false positives
```

See [`rules/README.md`](rules/README.md) for the field shapes per lane, what
this engine cannot express (aggregations, `timeframe`, correlation,
`keywords`, and -- silently -- wildcards in values), and why every rule needs a
firing test case. [`docs/RULE-SOURCES.md`](docs/RULE-SOURCES.md) lists the
upstream corpora per log source and their licences.
[`docs/RULES.md`](docs/RULES.md) is the catalogue.

### Authoring and the rulecheck gate

1. Write `rules/<lane>/<name>.yml` against the fields Vector actually emits
   (dotted paths such as `userIdentity.type` work; see `internal/decode`).
2. Write `rules/<lane>/<name>.tests.yml` from a **real** record: at least one
   `expected: true` case and, ideally, the near-misses that must not fire.
   Every event carries `source: <lane>`.
3. Run the gate and regenerate the catalogue:

   ```bash
   make rulecheck   # go test -run TestRules_ ./internal/rulecheck/
   make docs        # rewrites docs/RULES.md; CI fails if it is stale
   ```

`TestRules_*` compiles every lane exactly as the engine does at start, runs
every sidecar case, rejects a rule with no firing case, rejects `*`/`?` in a
value (sigma-go matches literally, so a wildcard is a rule that never fires or
-- under `not` -- one that fires on everything), rejects a stray file or
subdirectory in a lane, checks that no rule fires on a bare `{"source": ...}`
envelope, and reports two rules that fire on the same test event unless the
overlap is recorded as deliberate.

`hack/sigmaimport` imports SigmaHQ rules with fixtures from TrailAlerts; see
its README.

### Rule licences

Rules imported from SigmaHQ are licensed under the
[Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License)
and keep their original `author` and `references` in each file, which is the
attribution the licence requires. Rules from TrailAlerts are Apache-2.0 and are
attributed the same way. Rules written here carry `author: samma-io` and are
Apache-2.0 like the rest of the repository. See `NOTICE`.

## Correctness rules -- do not break these

1. **Alerts are published before the queue message is deleted.** `Flush` is
   where alerts become durable and `engine.Run` deletes only on `Accepted`.
   Deleting first turns an ordinary SQS retry into permanent loss of every
   detection in the object. `TestRun_DeletesOnlyAfterFlushSucceeds` and
   `TestRun_DoesNotDeleteWhenAlertPublishFails` are the guards.
2. **Zero rules is a startup failure.** An engine with no rules drains its
   queue, matches nothing, deletes every message, and makes queue depth go
   *down*. No dashboard tells that apart from a quiet week.
3. **Alert ids are content-derived**: `det_` + sha256 of schema version, rule
   id, log source, bucket, key and record index, NUL-separated
   (`alert.ID`) -- never the clock, the SQS message id, or the ruleset
   contents.
   Every path here is at-least-once; consumers must upsert on the id.
4. **Events reach the evaluator through `decode.MatchView`.** sigma-go's field
   lookup is a single flat map index, so a rule written `userIdentity.type`
   cannot see a nested object. Most upstream SigmaHQ rules use dotted paths.
5. **Numbers are normalised to `int` or `float64`.** A plain decode makes
   integers `float64`, which stringify as `1.78e+12` and miss;
   `Decoder.UseNumber` alone makes numeric modifiers *panic*.
6. **One bad record is skipped, a flood fails the object.** Aborting on one
   truncated line would send a 200,000-record object to the DLQ and take every
   good event with it.
7. **The AWS SDK stays in `internal/awsadapt`.** `TestPackages_DoNotImportTheAWSSDK`
   enforces it, so no unit test ever needs credentials.
8. **Every declared metric has an increment site.**
   `TestMetrics_EveryCollectorHasAnIncrementSite` enforces it -- a registered
   but never-incremented metric renders as a flat zero, and a flat zero reads
   as "nothing is wrong".

## Things that look wrong but are deliberate

- **Alpine, not distroless.** The ECS health check runs a shell command
  (`wget` against `/healthz`); distroless-static has no shell, so the check
  could never pass and the task would be killed as unhealthy.
- **`MaxNumberOfMessages = 1`.** Receiving ten would save API calls, but only
  the in-flight message gets a visibility heartbeat; the other nine would go
  visible mid-object and be handed to another task.
- **No poison/evidence bucket.** SQS already has a DLQ, so an unprocessable
  message becomes its own evidence by *not* being deleted. Writing a copy into
  the filtered bucket would risk an infinite, billable notification loop.
- **`publisher.Batcher` has no mutex.** One worker owns one batcher for one
  object. A shared batcher would let message B's flush make message A
  deletable while A's alerts were still buffered.
- **Per-rule panic recovery in `rules.Set.Match`.** sigma-go panics rather than
  erroring on some inputs. Failing the event would let one broken rule stop
  detection for every other rule and loop the object to the DLQ.
- **`detection_rule_errors_total` and `detection_panics_total` should always be
  zero.** Everything detectable at load time is rejected at load time, so a
  non-zero value is a bug or a dependency regression. Alarm on both. Each
  increment also writes one JSON log line at level `ERROR` with a fixed `msg`,
  which is what aws-siem's CloudWatch metric filters match -- do not reword
  them:

  | `msg` | When |
  |---|---|
  | `rule evaluation failed` | a rule errored or panicked on one event (the rule is skipped, the others still run) |
  | `panic recovered` | a panic anywhere else while handling a message (the message is left for redelivery) |

## Alert shape

```json
{
  "schema_version": "detection.alert.v1",
  "id": "det_3436971c209fbe1d...",
  "alerted_at": "2026-09-02T15:07:22.118Z",
  "log_source": "aws",
  "rule": {
    "id": "7f8b1c42-9d3e-4a51-b6c7-1e2f3a4b5c6d",
    "title": "CloudTrail Logging Disabled",
    "level": "high",
    "tags": ["attack.defense_evasion", "attack.t1562.008"],
    "file": "aws/cloudtrail_logging_disabled.yml"
  },
  "provenance": {
    "bucket": "filtered-123456789012-us-east-1",
    "key": "aws/date=2026-09-02/1756813200-6f2a91cc.ndjson.gz",
    "event_index": 0,
    "sqs_message_id": "600eba1f-..."
  },
  "event": { "...the record as Vector wrote it..." },
  "event_sha256": "...",
  "event_bytes": 412
}
```

`truncated: true` with no `event` means the alert exceeded the SQS message
limit; `provenance` still locates the original. The schema is specified in
aws-siem `docs/contracts/detection-alert-v1.md`.

## Layout

```
cmd/engine/             entrypoint: config, admin server, worker pool, shutdown
internal/config/        env -> Config, one joined error, no defaults for wiring
internal/source/        lane registry (a map, not a switch) and the key-prefix contract
internal/engine/        the core loop, the visibility heartbeat, dispositions
internal/decode/        S3 notification envelope; gzip sniff + streaming NDJSON;
                        number normalisation and the flattened match view
internal/rules/         rule loader (dir or S3), Sigma compilation, admission checks, matching
internal/publisher/     SQS alert batching: byte caps, partial-failure handling
internal/alert/         the alert envelope and its deterministic id
internal/awsadapt/      the only package that imports the AWS SDK
internal/metrics/       Prometheus collectors
internal/arch/          tests about the shape of the codebase, not its behaviour
internal/rulecheck/     CI gate on the rules/ tree
internal/rulesdoc/      renders docs/RULES.md from the rules tree
rules/<lane>/           Sigma rules + required .tests.yml sidecars
rules/examples/         org-specific templates with placeholders (not shipped)
hack/rulesdoc/          the `make docs` entrypoint
hack/sigmaimport/       SigmaHQ importer
hack/local/             localstack end-to-end
hack/scrub-check.sh     CI gate: no private identifiers in the tree
Dockerfile              golang:1.27-alpine builder -> alpine:3.21, non-root, pinned by digest;
                        bakes rules/ into /rules (ENGINE_RULES_DIR default)
```

## Development

```bash
make            # gofmt check, vet, test   (all in golang:1.27-alpine containers)
make test-race  # the shared ruleset is only safe because of a sigma-go detail
make rulecheck  # the rules gate alone
make docs       # regenerate docs/RULES.md after any rule change
make image      # ghcr.io/samma-io/detection-engine:<short sha>, linux/amd64
make push       # push it (IMAGE= and TAG= override both)
make scrub      # the private-identifier gate CI runs
```

CI (`.github/workflows/ci.yml`) runs gofmt, vet, `go test -race`, the
rulecheck gate, the catalogue freshness check, the scrub gate, gitleaks and a
Trivy scan of the built image on every pull request and push to `main`. CI
builds the image but never pushes it.

## Licence

Apache-2.0 (see `LICENSE`). Imported detection rules keep their own licences;
see `NOTICE` and [Rule licences](#rule-licences).
