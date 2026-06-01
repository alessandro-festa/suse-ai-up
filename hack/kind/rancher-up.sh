#!/usr/bin/env bash
# Bring up a local kind cluster with Rancher for UI extension testing.
# Pattern adapted from ~/Documents/dev/aif-nc/hack/kind/.
#
# Defaults: docker runtime (Rancher Desktop). Override with
#   KIND_EXPERIMENTAL_PROVIDER=podman ./rancher-up.sh
# Override versions via RANCHER_VERSION / CERT_MANAGER_VERSION env vars.

set -euo pipefail

CLUSTER_NAME="uniproxy-rancher"
RANCHER_VERSION="${RANCHER_VERSION:-v2.14.1}"
CERT_MANAGER_VERSION="${CERT_MANAGER_VERSION:-v1.20.2}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# rancher.localtest.me resolves to 127.0.0.1 via public DNS — no /etc/hosts
# edits required and survives home routers that strip RFC1918 DNS answers.
RANCHER_HOSTNAME="${RANCHER_HOSTNAME:-rancher.localtest.me}"

if kind get clusters | grep -qx "${CLUSTER_NAME}"; then
  echo "kind cluster ${CLUSTER_NAME} already exists; reusing."
else
  echo "==> creating kind cluster ${CLUSTER_NAME}"
  kind create cluster --config "${SCRIPT_DIR}/rancher.yaml"
fi

KUBECONTEXT="kind-${CLUSTER_NAME}"
KUBECTL=(kubectl --context "${KUBECONTEXT}")

echo "==> waiting for control-plane ready"
"${KUBECTL[@]}" wait --for=condition=Ready node --all --timeout=120s

echo "==> adding helm repos"
helm repo add jetstack https://charts.jetstack.io
helm repo add rancher-stable https://releases.rancher.com/server-charts/stable
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm repo update jetstack rancher-stable ingress-nginx >/dev/null

echo "==> installing ingress-nginx"
helm upgrade --install ingress-nginx ingress-nginx/ingress-nginx \
  --kube-context "${KUBECONTEXT}" \
  --namespace ingress-nginx --create-namespace \
  --set controller.hostPort.enabled=true \
  --set controller.hostPort.ports.http=80 \
  --set controller.hostPort.ports.https=443 \
  --set controller.service.type=ClusterIP \
  --set controller.ingressClassResource.default=true \
  --wait --timeout 5m

echo "==> installing cert-manager ${CERT_MANAGER_VERSION}"
helm upgrade --install cert-manager jetstack/cert-manager \
  --kube-context "${KUBECONTEXT}" \
  --namespace cert-manager --create-namespace \
  --version "${CERT_MANAGER_VERSION}" \
  --set installCRDs=true \
  --wait --timeout 5m

echo "==> waiting for cert-manager webhook"
"${KUBECTL[@]}" -n cert-manager wait --for=condition=Available deploy/cert-manager-webhook --timeout=120s

echo "==> installing Rancher ${RANCHER_VERSION} at https://${RANCHER_HOSTNAME}"
helm upgrade --install rancher rancher-stable/rancher \
  --kube-context "${KUBECONTEXT}" \
  --namespace cattle-system --create-namespace \
  --version "${RANCHER_VERSION#v}" \
  --set hostname="${RANCHER_HOSTNAME}" \
  --set replicas=1 \
  --set bootstrapPassword="" \
  --wait --timeout 10m

echo "==> waiting for Rancher rollout"
"${KUBECTL[@]}" -n cattle-system rollout status deploy/rancher --timeout=10m

BOOTSTRAP_PWD="$(${KUBECTL[@]} get secret --namespace cattle-system bootstrap-secret \
  -o go-template='{{.data.bootstrapPassword|base64decode}}' 2>/dev/null || echo '(retry: kubectl -n cattle-system get secret bootstrap-secret)')"

cat <<EOF

==> uniproxy-rancher ready
    kubectl context:  ${KUBECONTEXT}
    Rancher URL:      https://${RANCHER_HOSTNAME}
    Bootstrap pwd:    ${BOOTSTRAP_PWD}

Next steps to load the suse-ai-up UI extension:
  1. Open https://${RANCHER_HOSTNAME} (accept the self-signed cert).
  2. Set the admin password using the bootstrap password above.
  3. Preferences → Advanced Features → enable "Show extension developer load".
  4. Extensions → ⋮ → Developer Load:
       URL: http://host.docker.internal:4500/suse-ai-up-0.1.0/suse-ai-up-0.1.0.umd.min.js
  5. In another shell, from the repo root:
       cd ui && yarn build-pkg suse-ai-up && yarn serve-pkgs

Tear down with: hack/kind/rancher-down.sh
EOF
