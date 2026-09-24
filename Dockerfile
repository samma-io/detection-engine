# syntax=docker/dockerfile:1

# Builder pinned to the Go minor in go.mod (1.25) and to a multi-arch index
# digest, so a moving tag cannot change what a release was built with.
FROM --platform=$BUILDPLATFORM golang:1.25-alpine@sha256:1ae0735f00daffa3aaf1363a5184c0d2dc55c78e3db4ec70241cdac97bf84b59 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# TARGETARCH rather than a hard-coded amd64: the image is published for
# linux/amd64 and linux/arm64, and a pinned amd64 binary on an arm64 host
# would be emulated silently -- slower and harder to notice than a build
# failure.
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=none
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
      -o /out/engine ./cmd/engine

# Alpine rather than distroless, deliberately: the ECS health check runs a
# shell command (wget against /healthz), and distroless/static has no shell,
# so the check could never pass and the task would be killed as unhealthy.
FROM alpine:3.21@sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507
RUN apk add --no-cache ca-certificates wget \
 && adduser -D -u 65532 engine
COPY --from=build /out/engine /app/engine
USER 65532:65532
EXPOSE 9090
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://localhost:9090/healthz >/dev/null || exit 1
ENTRYPOINT ["/app/engine"]
