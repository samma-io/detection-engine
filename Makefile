# Every Go and Docker step runs in a container so the toolchain is the same on
# every machine and in CI. Set GO_IMAGE to override the pin. The default is
# the Dockerfile's build image, so it satisfies the go directive in go.mod;
# bump the two together.
GO_IMAGE   ?= golang:1.27-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c

# We build and push our own images; there are no release tags. The tag is
# whatever the builder passes (aws-siem hack/build-images.sh passes the short
# sha), and the default is the same. linux/amd64 because every ECS task
# definition in aws-siem is X86_64.
IMAGE      ?= ghcr.io/samma-io/detection-engine
TAG        ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
PLATFORM   ?= linux/amd64
VERSION    ?= $(TAG)
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)

# A named volume for the module cache so repeated runs do not re-download.
GO_RUN = docker run --rm \
  -v "$(CURDIR)":/w -w /w \
  -v detection-engine-gomod:/go/pkg/mod \
  -e CGO_ENABLED=0 -e GOFLAGS=-buildvcs=false \
  $(GO_IMAGE)

.PHONY: all fmt fmt-check vet test test-race rulecheck lint build image push scrub \
        docs docs-check local-up local-down local-seed local-run local-verify

# The default gate. Run this before opening a PR.
all: fmt-check vet test

fmt:
	$(GO_RUN) gofmt -w .

fmt-check:
	$(GO_RUN) sh -c 'test -z "$$(gofmt -l .)" || { echo "gofmt needed on:"; gofmt -l .; exit 1; }'

vet:
	$(GO_RUN) go vet ./...

test:
	$(GO_RUN) go test ./...

## The race detector matters here: one compiled ruleset is shared by every
## worker goroutine, and that is safe only because of an unasserted internal
## detail of sigma-go. TestMatch_IsSafeForConcurrentUse is what notices a
## dependency bump breaking it. The race detector needs cgo, hence CGO_ENABLED=1.
test-race:
	docker run --rm -v "$(CURDIR)":/w -w /w -v detection-engine-gomod:/go/pkg/mod \
	  -e CGO_ENABLED=1 -e GOFLAGS=-buildvcs=false $(GO_IMAGE) go test -race ./...

## The CI gate on rules/: compile, positive test case, glob lint, overlap.
rulecheck:
	$(GO_RUN) go test -run 'TestRules_' -v ./internal/rulecheck/

lint:
	docker run --rm -v "$(CURDIR)":/w -w /w golangci/golangci-lint:v2.4.0 golangci-lint run

## Regenerate docs/RULES.md from the rules tree. Run this after any rule
## change -- TestRules_CatalogIsUpToDate fails if you don't.
docs:
	$(GO_RUN) go run ./hack/rulesdoc -root .

docs-check:
	$(GO_RUN) go run ./hack/rulesdoc -root . -check

build:
	$(GO_RUN) env GOOS=linux GOARCH=amd64 go build -trimpath \
	  -ldflags "-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)" \
	  -o bin/engine ./cmd/engine

## Build $(IMAGE):$(TAG), rules baked in at /rules.
image:
	docker build --platform $(PLATFORM) \
	  --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) \
	  -t $(IMAGE):$(TAG) .

## Push $(IMAGE):$(TAG). Needs a `docker login ghcr.io` with write:packages.
push:
	docker push $(IMAGE):$(TAG)

## Both scrub gates that CI runs on every push.
scrub:
	./hack/scrub-check.sh .

# --- local end-to-end against localstack (see README "Run standalone") ---

## Start localstack with s3 and sqs.
local-up:
	docker compose -f hack/local/docker-compose.yml up -d --wait

## Stop localstack and delete its state.
local-down:
	docker compose -f hack/local/docker-compose.yml down -v

## Create the buckets and queues, upload the rules, and wire the notification.
local-seed:
	./hack/local/seed.sh

## Run the engine image against localstack (builds the image first).
local-run: image
	IMAGE=$(IMAGE):$(TAG) ./hack/local/run.sh

## Put a matching object in the filtered bucket and assert an alert arrives.
local-verify:
	./hack/local/verify.sh
