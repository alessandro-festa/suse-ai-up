# SUSE AI Up — Rancher Dashboard extension

This directory hosts the Rancher Dashboard extension for `suse-ai-up`. It is a Yarn-workspaces monorepo that wraps a single extension package at `pkg/suse-ai-up/`, built against [`@rancher/shell`](https://www.npmjs.com/package/@rancher/shell) 3.x for Rancher 2.10+ (Extensions API V3).

Replaces the standalone repo at https://github.com/SUSE/suse-ai-up-ext — recreated from scratch so the UI evolves alongside the backend in one repo.

## Layout

```
ui/
  package.json                  workspace root (Shell scripts, deps)
  pkg/suse-ai-up/
    index.ts                    plugin entry: addProduct + addRoutes
    product.ts                  product registration + side-menu wiring
    routing.ts                  six top-level routes
    config/                     product constants, API config, storage keys
    components/                 AiUp* visual primitives (page, card, pill, toolbar, gallery)
    pages/                      Home / MCPGateway / MCPRegistry / VirtualMCP / SmartAgents / Settings
    services/                   axios client + typed service per backend resource group
    store/suse-ai-up.ts         namespaced Vuex module (auth, backend URL, banners)
    styles/tokens.scss          spacing + brand token; everything else uses Rancher CSS vars
    assets/logo*.svg            placeholder green-accent SVGs (swap in real brand later)
```

## Prerequisites

- **Node 24** — pin enforced via `.nvmrc`. `nvm use 24` before any yarn command (Node 26+ trips a transitive engine cap in `@achrinza/node-ipc`).
- **Yarn 1.x** (Classic).
- For in-cluster testing: `kind`, `helm`, `kubectl`, plus `docker` (Rancher Desktop is fine) or `podman`.

## Develop

```
nvm use 24
yarn install                                    # first time only
API=https://<your-rancher-url> yarn dev         # hot reload on https://127.0.0.1:8005
```

`API` should point at a running Rancher instance (the kind cluster below works).

## Build & serve for Developer Load

```
yarn build-pkg suse-ai-up                       # output → dist-pkg/suse-ai-up-0.1.0/
yarn serve-pkgs                                 # Express server on http://localhost:4500
```

Catalog endpoint: `GET http://localhost:4500/` returns the package metadata array.
Bundle URL: `http://localhost:4500/suse-ai-up-0.1.0/suse-ai-up-0.1.0.umd.min.js`.

## End-to-end smoke (local Rancher in kind)

```
./hack/kind/rancher/up.sh                       # ~5 min; brings up Rancher v2.14.1
# in another shell:
cd ui && nvm use 24 && yarn build-pkg suse-ai-up && yarn serve-pkgs
```

Then in the Rancher UI:
1. Log in with the bootstrap password the script printed.
2. **Preferences → Advanced Features → Show extension developer load** → enable.
3. **Extensions → ⋮ → Developer Load**, paste the bundle URL above.

See `hack/kind/rancher/README.md` for tear-down and troubleshooting.

## What's stubbed (Phase B/D scaffold)

- All six pages render the AIF-style layout (header + toolbar + card gallery) but only **Home** calls the backend (`GET /health`).
- The service layer (`services/*.ts`) covers the full HTTP API surface (~30 endpoints across adapters, registry, users, groups, plugins, discovery, auth) — wiring per-page lands in follow-up PRs.
- No i18n yet; strings are hardcoded English (matches the old extension).
- No Helm chart for catalog distribution yet.
- RouteAssignment UI is intentionally absent — blocked on issue #67 (server-scoped HTTP vs route-referenced CRD model decision).

## Visual conventions (AIF-style)

- All colors via Rancher CSS custom properties (`--primary`, `--success`, `--warning`, `--border`, `--body-text`, …). Dark/light mode works without overrides.
- Single hardcoded brand color: `#30BA78` in `styles/tokens.scss` and the placeholder SVGs.
- Spacing scale: 20px page padding, 15px gallery gap, 10px internal card gap.
- Card gallery: `grid auto-fill minmax(360px, 1fr)`.
- Icons come from Rancher's icon library (`icon-*` class names) — don't ship custom SVGs except the logo mark.

## Conventions

- TypeScript everywhere — `.vue` files use `<script lang="ts">` when they reference type annotations.
- Composition API (`defineComponent({ setup() })`), not Options API.
- Service modules export a single named API object (e.g., `adaptersApi`) rather than loose functions, to keep call sites greppable.
- All localStorage keys live in `config/storage.ts` — never hardcode a key elsewhere.
