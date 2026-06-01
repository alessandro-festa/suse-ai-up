#!/usr/bin/env bash
# Tear down the uniproxy-rancher kind cluster.
set -euo pipefail

CLUSTER_NAME="uniproxy-rancher"

if kind get clusters | grep -qx "${CLUSTER_NAME}"; then
  echo "==> deleting kind cluster ${CLUSTER_NAME}"
  kind delete cluster --name "${CLUSTER_NAME}"
else
  echo "kind cluster ${CLUSTER_NAME} not present; nothing to do."
fi
