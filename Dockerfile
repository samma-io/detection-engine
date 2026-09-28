# syntax=docker/dockerfile:1

# Builder pinned to the Go minor in go.mod (1.25) and to a multi-arch index
# digest, so a moving tag cannot change what an image was built with.
FROM --platform=$BUILDPLATFORM golang:1.25-alpine@sha256:1ae0735f00daffa3aaf1363a5184c0d2dc55c78e3db4ec70241cdac97bf84b59 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# TARGETARCH rather than a hard-coded amd64: `make image` builds linux/amd64
# for ECS, but a local arm64 build must get an arm64 binary rather than one
# emulated silently -- slower and harder to notice than a build failure.
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=none
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
      -o /out/engine ./cmd/engine

# The shippable rules tree, without the .tests.yml sidecars (the engine would
# refuse to start on one) and rules/examples/ (placeholder values). Done in
# its own stage so the final image gets one clean COPY and never carries the
# deleted files in a layer.
FROM alpine:3.21@sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507 AS rules
COPY rules/ /rules/
RUN rm -rf /rules/examples \
 && find /rules -type f ! -name '*.yml' ! -name '*.yaml' -delete \
 && find /rules -type f -name '*.tests.yml' -delete \
 && find /rules -mindepth 1 -type d -empty -delete \
 && test -s /rules/aws/sigma-config.yml

# Alpine rather than distroless, deliberately: the ECS health check runs a
# shell command (wget against /healthz), and distroless/static has no shell,
# so the check could never pass and the task would be killed as unhealthy.
FROM alpine:3.21@sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507
RUN apk add --no-cache ca-certificates wget \
 && adduser -D -u 65532 engine
COPY --from=build /out/engine /app/engine
# Read-only for the engine user: the ruleset is what the image was built with,
# and ENGINE_RULES_BUCKET is the override for an installation that ships its own.
COPY --from=rules --chown=0:0 /rules/ /rules/
ENV ENGINE_RULES_DIR=/rules
USER 65532:65532
EXPOSE 9090
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://localhost:9090/healthz >/dev/null || exit 1
ENTRYPOINT ["/app/engine"]
