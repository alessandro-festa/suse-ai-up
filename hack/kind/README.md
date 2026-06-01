# Kind smoke clusters

Three named kind clusters cover the development matrix. Pattern adapted from `~/Documents/dev/aif-nc/hack/kind/`.

| Cluster | Purpose | Bring up |
|---------|---------|----------|
| `uniproxy-smoke` | Operator smoke. CRDs install, helm-installed manager comes up, sample CRs visible. Single command, dev-friendly output, no hard pass/fail. | `make smoke-up` |
| `uniproxy-rancher` | Rancher UI extension dev loop. Rancher v2.14.1 + cert-manager v1.20.2 + nginx-ingress. | `make rancher-up` |
| `uniproxy-e2e` | CI variant of the smoke target. Quieter output, **non-zero exit** if the manager Deployment doesn't roll out, the leader-election lease isn't acquired, or the pod isn't `Running`. | `make e2e-up` |

Cluster names are prefixed `uniproxy-` to avoid colliding with the binary-name `suse-ai-up` (which is also the Helm release name); when you `kind get clusters` you can see at a glance which clusters belong to this repo.

## Common workflow (developer)

```bash
# 1. Build the operator image locally (Dockerfile produces ./suse-ai-up).
make docker-build IMG=suse-ai-up-manager:latest

# 2. Bring up the smoke cluster and helm-install the chart against the
#    just-built image. Re-running is idempotent — uses helm upgrade
#    under the hood.
make smoke-up IMG=suse-ai-up-manager:latest

# 3. Inspect.
kubectl --context kind-uniproxy-smoke -n suse-ai-up get pods
kubectl --context kind-uniproxy-smoke get adapters,mcpregistries,mcpservers,virtualmcproutes,agents -A

# 4. Tear down when done.
make smoke-down
```

For the Rancher UI dev loop see [`rancher-README.md`](./rancher-README.md). After `make rancher-up`, `make rancher-url` and `make rancher-password` print what you need to log in.

## CI flow

```bash
make docker-build IMG=$IMG
make e2e-up      IMG=$IMG E2E_TIMEOUT=10m
make e2e-down
```

`e2e-up.sh` exits non-zero on:
- Manager Deployment failing to roll out within `E2E_TIMEOUT` (default `5m`).
- Leader-election lease (`d0141a56.suse.com`) not appearing within 60 s of the rollout.
- No `app.kubernetes.io/name=suse-ai-up` pod reaching `Running` phase.

Individual sample CRs not reaching `Status.Phase=Ready` are surfaced but don't fail the run — some demo samples deliberately reference resources we don't ship (e.g. external GitHub adapters that need secrets only present in production).

## Prerequisites

- `kind` v0.20+
- `helm` v3.x
- `kubectl`
- `docker` (default) or `podman` (`export KIND_EXPERIMENTAL_PROVIDER=podman` for all three scripts)
- For `make rancher-url` and `make rancher-password`: `cert-manager` and `rancher` Helm repos are added automatically by `rancher-up.sh`.

## Renamed from `suse-ai-up-rancher` → `uniproxy-rancher`

If you had the pre-P2.8 Rancher cluster running locally (`suse-ai-up-rancher`), delete it explicitly before bringing up the new one — the rename doesn't carry state forward:

```bash
kind delete cluster --name suse-ai-up-rancher
make rancher-up
```

## Troubleshooting

**`kind create cluster` hangs on macOS + podman.** Make sure `podman machine` is started (`podman machine start`) and has enough memory (the default 2 GB is borderline for the rancher topology — bump to 4 GB).

**Port 80/443 already in use.** The `rancher.yaml` cluster config binds host ports 80 and 443 for nginx-ingress. Stop other listeners (`brew services stop nginx`, `lsof -i:80`).

**`make smoke-up` says "image not found locally; chart will pull".** You haven't run `make docker-build` yet, OR you ran it with a different `IMG` tag than `make smoke-up` is using. Match the `IMG=` variable across both targets.

**Rancher bootstrap password missing.** The Helm install needs ~30 s after rollout before the secret materializes. Re-run `make rancher-password` after a short wait.
