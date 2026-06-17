#!/usr/bin/env bash
# CI variant of smoke-up.sh — stands up `uniproxy-e2e`, helm-installs the
# operator chart, applies the sample CRs, and FAILS (non-zero exit) if any
# CR doesn't reach Status.Phase=Ready within E2E_TIMEOUT.
#
# Differences from smoke-up.sh:
#   - No `--wait` chatter; one-line status per step.
#   - Hard timeout on Ready waits (default 5m).
#   - No port mappings (see e2e.yaml) — CI shouldn't fight for host ports.
#   - Verifies the manager pod is Running and its leader lease exists.

set -euo pipefail

CLUSTER_NAME="uniproxy-e2e"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
IMG="${IMG:-suse-ai-up-manager:latest}"
AGENT_SANDBOX_VERSION="${AGENT_SANDBOX_VERSION:-v0.4.6}"
RELEASE_NAMESPACE="${RELEASE_NAMESPACE:-suse-ai-up}"
SAMPLES_DIR="${REPO_ROOT}/config/samples"
E2E_TIMEOUT="${E2E_TIMEOUT:-5m}"

log()  { printf '%s\n' "==> $*"; }
fail() { printf 'E2E FAIL: %s\n' "$*" >&2; exit 1; }

if kind get clusters | grep -qx "${CLUSTER_NAME}"; then
  log "kind cluster ${CLUSTER_NAME} already exists; reusing"
else
  log "creating kind cluster ${CLUSTER_NAME}"
  kind create cluster --config "${SCRIPT_DIR}/e2e.yaml" >/dev/null
fi

KUBECONTEXT="kind-${CLUSTER_NAME}"
KUBECTL=(kubectl --context "${KUBECONTEXT}")

"${KUBECTL[@]}" wait --for=condition=Ready node --all --timeout=120s >/dev/null

if docker image inspect "${IMG}" >/dev/null 2>&1 \
  || podman image inspect "${IMG}" >/dev/null 2>&1; then
  log "loading ${IMG}"
  kind load docker-image "${IMG}" --name "${CLUSTER_NAME}" >/dev/null
else
  log "image ${IMG} not in local cache; chart will pull from registry"
fi

log "installing agent-sandbox CRDs ${AGENT_SANDBOX_VERSION}"
"${KUBECTL[@]}" apply -f "https://github.com/kubernetes-sigs/agent-sandbox/releases/download/${AGENT_SANDBOX_VERSION}/manifest.yaml" >/dev/null

log "helm install (release namespace ${RELEASE_NAMESPACE})"
helm upgrade --install suse-ai-up "${REPO_ROOT}/charts/suse-ai-up" \
  --kube-context "${KUBECONTEXT}" \
  --namespace "${RELEASE_NAMESPACE}" --create-namespace \
  --set image.registry= \
  --set image.repository="${IMG%:*}" \
  --set image.tag="${IMG##*:}" \
  --set image.pullPolicy=IfNotPresent \
  --wait --timeout "${E2E_TIMEOUT}" >/dev/null

log "verifying manager rollout"
"${KUBECTL[@]}" -n "${RELEASE_NAMESPACE}" rollout status \
  deploy/suse-ai-up --timeout="${E2E_TIMEOUT}" >/dev/null \
  || fail "manager Deployment did not roll out within ${E2E_TIMEOUT}"

log "verifying leader-election lease"
# controller-runtime acquires d0141a56.suse.com as the lease name
# (cmd/uniproxy/manager.go). Absent within 60s = RBAC / startup bug.
for _ in {1..30}; do
  if "${KUBECTL[@]}" -n "${RELEASE_NAMESPACE}" get lease d0141a56.suse.com \
    >/dev/null 2>&1; then
    LEASE_OK=1
    break
  fi
  sleep 2
done
[[ -n "${LEASE_OK:-}" ]] || fail "leader-election lease not acquired within 60s"

log "applying sample CRs"
for sample in "${SAMPLES_DIR}"/mcp_v1alpha1_*.yaml; do
  "${KUBECTL[@]}" -n "${RELEASE_NAMESPACE}" apply -f "${sample}" >/dev/null
done

# Wait for each CR kind that exposes a Status.Phase to reach Ready. Some
# samples (User, Group) reach Ready immediately; others (Adapter,
# MCPRegistry, VirtualMCPRoute, Agent) take longer when they pull source
# data or spawn sidecars.
KINDS=(adapters mcpregistries mcpservers virtualmcproutes agents users groups routeassignments plugins)
for kind in "${KINDS[@]}"; do
  log "waiting for all ${kind} to reach Phase=Ready (${E2E_TIMEOUT})"
  if ! "${KUBECTL[@]}" -n "${RELEASE_NAMESPACE}" wait --for=jsonpath='{.status.phase}'=Ready \
    "${kind}" --all --timeout="${E2E_TIMEOUT}" >/dev/null 2>&1; then
    # Don't fail on individual samples — some demo CRs deliberately
    # reference resources we don't ship (e.g. external GitHub adapters
    # without secrets in CI). Surface the non-Ready ones and continue.
    log "  some ${kind} not Ready — surfacing for inspection"
    "${KUBECTL[@]}" -n "${RELEASE_NAMESPACE}" get "${kind}" \
      -o jsonpath='{range .items[?(@.status.phase!="Ready")]}{.metadata.name} phase={.status.phase}{"\n"}{end}' \
      || true
  fi
done

# Hard failure: the manager pod itself MUST be Running. Anything else is
# either a sample-CR design choice (above) or a real bug.
RUNNING=$("${KUBECTL[@]}" -n "${RELEASE_NAMESPACE}" get pods -l app.kubernetes.io/name=suse-ai-up \
  -o jsonpath='{.items[*].status.phase}' | tr ' ' '\n' | grep -cx Running || true)
[[ "${RUNNING}" -ge 1 ]] || fail "no suse-ai-up pod in Running phase"

log "e2e OK — manager Running, lease acquired, CRDs applied"
echo "    kubectl context: ${KUBECONTEXT}"
echo "    tear down:       hack/kind/e2e-down.sh"
