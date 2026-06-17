#!/usr/bin/env bash
# Bring up the `uniproxy-smoke` kind cluster used to verify the operator
# end-to-end: CRDs install cleanly, helm-installed manager comes up
# leader-elected, sample CRs (Adapter, MCPRegistry, VirtualMCPRoute,
# Agent) reach Status.Phase=Ready. No Rancher, no UI — see rancher-up.sh
# for the UI-extension loop.
#
# Pattern adapted from ~/Documents/dev/aif-nc/hack/kind/.
#
# Defaults: docker runtime (Rancher Desktop). Override with
#   KIND_EXPERIMENTAL_PROVIDER=podman ./smoke-up.sh
# Image is built + loaded by `make smoke-load` separately; this script
# only stands up the cluster + the chart pointed at IMG.

set -euo pipefail

CLUSTER_NAME="uniproxy-smoke"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
IMG="${IMG:-suse-ai-up-manager:latest}"
AGENT_SANDBOX_VERSION="${AGENT_SANDBOX_VERSION:-v0.4.6}"
RELEASE_NAMESPACE="${RELEASE_NAMESPACE:-suse-ai-up}"
SAMPLES_DIR="${REPO_ROOT}/config/samples"
WAIT_TIMEOUT="${WAIT_TIMEOUT:-5m}"

if kind get clusters | grep -qx "${CLUSTER_NAME}"; then
  echo "kind cluster ${CLUSTER_NAME} already exists; reusing."
else
  echo "==> creating kind cluster ${CLUSTER_NAME}"
  kind create cluster --config "${SCRIPT_DIR}/smoke.yaml"
fi

KUBECONTEXT="kind-${CLUSTER_NAME}"
KUBECTL=(kubectl --context "${KUBECONTEXT}")

echo "==> waiting for control-plane ready"
"${KUBECTL[@]}" wait --for=condition=Ready node --all --timeout=120s

# Load the image only if it's already in the local docker / podman cache.
# Building is left to `make docker-build` so smoke-up can be re-run quickly
# during iteration without pulling.
if docker image inspect "${IMG}" >/dev/null 2>&1 \
  || podman image inspect "${IMG}" >/dev/null 2>&1; then
  echo "==> loading ${IMG} into ${CLUSTER_NAME}"
  kind load docker-image "${IMG}" --name "${CLUSTER_NAME}"
else
  echo "==> image ${IMG} not found locally; helm install will pull from the registry"
fi

echo "==> installing agent-sandbox CRDs ${AGENT_SANDBOX_VERSION}"
"${KUBECTL[@]}" apply -f "https://github.com/kubernetes-sigs/agent-sandbox/releases/download/${AGENT_SANDBOX_VERSION}/manifest.yaml"

echo "==> helm install / upgrade suse-ai-up (release namespace: ${RELEASE_NAMESPACE})"
# The chart bundles CRDs under charts/suse-ai-up/crds/ so the first
# install brings them along; subsequent upgrades on this cluster reuse
# the already-installed CRDs (Helm 3 doesn't re-apply on upgrade).
helm upgrade --install suse-ai-up "${REPO_ROOT}/charts/suse-ai-up" \
  --kube-context "${KUBECONTEXT}" \
  --namespace "${RELEASE_NAMESPACE}" --create-namespace \
  --set image.registry= \
  --set image.repository="${IMG%:*}" \
  --set image.tag="${IMG##*:}" \
  --set image.pullPolicy=IfNotPresent \
  --wait --timeout "${WAIT_TIMEOUT}"

echo "==> waiting for manager deployment rollout"
"${KUBECTL[@]}" -n "${RELEASE_NAMESPACE}" rollout status \
  deploy/suse-ai-up --timeout="${WAIT_TIMEOUT}"

echo "==> applying sample CRs from config/samples/"
# Skip the kustomization.yaml index — it lists files we apply individually
# so a failure on one sample doesn't poison the whole batch.
for sample in "${SAMPLES_DIR}"/mcp_v1alpha1_*.yaml; do
  echo "  -> $(basename "${sample}")"
  "${KUBECTL[@]}" -n "${RELEASE_NAMESPACE}" apply -f "${sample}"
done

# The smoke target is a developer convenience — we DON'T fail on Ready
# timeouts here (samples may legitimately Pending while their referenced
# adapters spin up sidecar Deployments). Use e2e-up.sh for the CI variant
# that does fail loudly.
echo
echo "==> uniproxy-smoke ready"
cat <<EOF
    kubectl context:  ${KUBECONTEXT}
    namespace:        ${RELEASE_NAMESPACE}
    image:            ${IMG}

Inspect:
  kubectl --context ${KUBECONTEXT} -n ${RELEASE_NAMESPACE} get pods
  kubectl --context ${KUBECONTEXT} get adapters,mcpregistries,mcpservers,virtualmcproutes,agents -A

Port-forward the HTTP API:
  kubectl --context ${KUBECONTEXT} -n ${RELEASE_NAMESPACE} port-forward svc/suse-ai-up-service 8911:8911

Tear down: hack/kind/smoke-down.sh
EOF
