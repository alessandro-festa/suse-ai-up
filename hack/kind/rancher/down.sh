#!/usr/bin/env bash
# Tear down the suse-ai-up-rancher kind cluster.
set -euo pipefail

CLUSTER_NAME="suse-ai-up-rancher"

if kind get clusters | grep -qx "${CLUSTER_NAME}"; then
  echo "==> deleting kind cluster ${CLUSTER_NAME}"
  kind delete cluster --name "${CLUSTER_NAME}"
else
  echo "kind cluster ${CLUSTER_NAME} not present; nothing to do."
fi
