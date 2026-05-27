# syntax=docker/dockerfile:1
#
# Multi-stage Dockerfile producing two images via --target:
#   docker build --target=uniproxy -t suse-ai-up:latest .          (default)
#   docker build --target=manager  -t suse-ai-up-manager:latest .
#
# The default target is the first runtime stage (uniproxy) so existing
# `docker build .` invocations keep producing the HTTP server image.

# --- builder ---------------------------------------------------------------
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder

ARG TARGETARCH
ENV CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH}

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -ldflags="-w -s" -o /out/uniproxy ./cmd/uniproxy
RUN go build -ldflags="-w -s" -o /out/manager  ./cmd/manager

# --- uniproxy runtime (default) -------------------------------------------
FROM registry.suse.com/bci/bci-base:16.0 AS uniproxy

RUN zypper --non-interactive install ca-certificates timezone && \
    useradd -r -s /bin/bash -u 1000 mcpuser

WORKDIR /home/mcpuser

COPY --from=builder /out/uniproxy             ./suse-ai-up
COPY --from=builder /app/hack/registry        ./hack/registry
COPY --from=builder /app/docs                 ./docs

RUN chown -R mcpuser:mcpuser suse-ai-up hack docs

USER 1000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD nc -z localhost 8911 || exit 1

EXPOSE 8911 3911

CMD ["./suse-ai-up"]

# --- manager runtime (operator) -------------------------------------------
FROM gcr.io/distroless/static:nonroot AS manager

WORKDIR /

COPY --from=builder /out/manager .

USER 65532:65532

ENTRYPOINT ["/manager"]
