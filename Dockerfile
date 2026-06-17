# syntax=docker/dockerfile:1
#
# Single-stage Dockerfile producing the consolidated operator image. The
# uniproxy binary dispatches on subcommand: `all` (default) runs the
# controller-runtime reconcilers and the HTTP server in-process;
# `manager` runs reconcilers only; `serve` runs the HTTP server only in
# legacy file-mode. See P2.6 in issue #30.
#
# Base is bci-base (not distroless) because the HTTP server needs to write
# initial users/groups, mount the registry config + docs ConfigMaps, and
# pass an `nc`-based HEALTHCHECK; distroless lacks the shell + utilities.

# --- builder ---------------------------------------------------------------
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder

ARG TARGETARCH
ENV CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH}

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -ldflags="-w -s" -o /out/uniproxy ./cmd/uniproxy

# --- runtime --------------------------------------------------------------
FROM registry.suse.com/bci/bci-base:16.0

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

ENTRYPOINT ["./suse-ai-up"]
CMD ["all"]
