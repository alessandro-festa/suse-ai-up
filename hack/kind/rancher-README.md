# Local Rancher in kind for UI extension testing

A single-node kind cluster running Rancher v2.14.1, used to Developer-Load the `ui/` Rancher Dashboard extension during development. Pattern adapted from `~/Documents/dev/aif-nc/hack/kind/`.

## Prerequisites

- `docker` (Rancher Desktop is fine) or `podman` with `KIND_EXPERIMENTAL_PROVIDER=podman`
- `kind`, `helm`, `kubectl`
- ports `80` and `443` free on localhost (the cluster maps them to ingress-nginx)
- Node 24 (`nvm use 24` — see `ui/.nvmrc`)

## Bring up

```
./hack/kind/rancher/up.sh
```

Takes ~3–5 minutes. The script idempotently reuses an existing cluster of the same name.

Defaults can be overridden via env:

```
RANCHER_VERSION=v2.14.1 \
CERT_MANAGER_VERSION=v1.20.2 \
RANCHER_HOSTNAME=rancher.localtest.me \
./hack/kind/rancher/up.sh
```

`rancher.localtest.me` resolves to `127.0.0.1` via public DNS — no `/etc/hosts` work needed.

## Load the extension

From the repo root, in a second shell:

```
cd ui
nvm use 24
yarn install                  # first time only
yarn build-pkg suse-ai-up
yarn serve-pkgs               # leaves an Express server on :4500
```

In the Rancher UI:

1. Log in with the bootstrap password the script printed.
2. **Preferences → Advanced Features → Show extension developer load** → enable.
3. **Extensions → ⋮ (top right) → Developer Load**.
4. URL: `http://host.docker.internal:4500/suse-ai-up-0.1.0/suse-ai-up-0.1.0.umd.min.js`
5. Confirm.

The **SUSE AI Up** product appears in the global product list with the six pages (Home, MCP Gateway, MCP Registry, Virtual MCP, Smart Agents, Settings).

## Tear down

```
./hack/kind/rancher/down.sh
```

## Troubleshooting

- **`host.docker.internal` not resolving from the Rancher pod** → on some runtimes you need the host's actual IP. Use `ipconfig getifaddr en0` (macOS) and substitute it in the Developer Load URL.
- **Bootstrap password missing** → `kubectl --context kind-suse-ai-up-rancher -n cattle-system get secret bootstrap-secret -o go-template='{{.data.bootstrapPassword|base64decode}}'`
- **Rancher pod CrashLoopBackOff after ~10 min** → bump the host VM's memory (Rancher Desktop → Preferences → Virtual Machine).
- **Backend health card on the Home page shows "Unreachable"** → expected when no `suse-ai-up` backend is running in the cluster yet. Set the backend URL in the extension's Settings page or run the Go binary locally and point at `http://host.docker.internal:8911`.
