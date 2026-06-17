# syntax=docker/dockerfile:1
#
# Multi-runtime mcp-proxy sidecar image.
# Runs mcp-proxy (Mode 2 — server-side) which spawns a STDIO-based MCP
# server as a child process and exposes it as streamable-HTTP on a port.
#
# Included runtimes:
#   - Python 3.11 + uv (for python-based MCP servers)
#   - Node.js 22 + npm (for npx-based MCP servers)
#
# Usage inside a Sandbox pod:
#   mcp-proxy --port=8000 uv run mcp-bugzilla ...
#   mcp-proxy --port=8000 npx -y @modelcontextprotocol/server-github

FROM registry.suse.com/bci/python:3.11

RUN zypper --non-interactive install ca-certificates nodejs22 npm22 && \
    zypper clean --all

RUN pip install --no-cache-dir mcp-proxy uv

USER 1000

ENTRYPOINT ["mcp-proxy"]
