#!/usr/bin/env bash
# Local installation of agentgateway on a kind cluster using locally built images.
# Usage: ./local-install.sh
#
# Prerequisites: docker, kind, kubectl, helm, go, cargo (Rust toolchain)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTROLLER_DIR="${REPO_ROOT}/controller"

# Configurable variables (override via env)
VERSION="${VERSION:-v1.0.1-dev}"
CLUSTER_NAME="${CLUSTER_NAME:-kind}"
INSTALL_NAMESPACE="${INSTALL_NAMESPACE:-agentgateway-system}"
IMAGE_REGISTRY="${IMAGE_REGISTRY:-ghcr.io/agentgateway}"

echo "==> Using VERSION=${VERSION}, CLUSTER=${CLUSTER_NAME}, NAMESPACE=${INSTALL_NAMESPACE}"

#---------------------------------------------------------------------------
# 1. Create kind cluster (if it doesn't already exist)
#---------------------------------------------------------------------------
echo "==> Ensuring kind cluster '${CLUSTER_NAME}' exists..."
if ! kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    make -C "${CONTROLLER_DIR}" kind-create CLUSTER_NAME="${CLUSTER_NAME}"
else
    echo "    Cluster '${CLUSTER_NAME}' already exists, skipping creation."
fi

#---------------------------------------------------------------------------
# 2. Install Gateway API CRDs (experimental channel)
#---------------------------------------------------------------------------
echo "==> Installing Gateway API CRDs..."
make -C "${CONTROLLER_DIR}" gw-api-crds

#---------------------------------------------------------------------------
# 3. Build the proxy (data-plane) Docker image from the root Dockerfile
#---------------------------------------------------------------------------
echo "==> Building proxy (data-plane) image: ${IMAGE_REGISTRY}/agentgateway:${VERSION}..."
make -C "${REPO_ROOT}" docker IMAGE_TAG="${VERSION}"

#---------------------------------------------------------------------------
# 4. Build the controller (control-plane) Docker image
#---------------------------------------------------------------------------
echo "==> Building controller image: ${IMAGE_REGISTRY}/agentgateway-controller:${VERSION}..."
make -C "${CONTROLLER_DIR}" agentgateway-controller-docker VERSION="${VERSION}"

#---------------------------------------------------------------------------
# 5. Load both images into kind
#---------------------------------------------------------------------------
echo "==> Loading images into kind cluster '${CLUSTER_NAME}'..."
kind load docker-image "${IMAGE_REGISTRY}/agentgateway:${VERSION}" --name "${CLUSTER_NAME}"
kind load docker-image "${IMAGE_REGISTRY}/agentgateway-controller:${VERSION}" --name "${CLUSTER_NAME}"

#---------------------------------------------------------------------------
# 6. Package and deploy agentgateway via Helm
#---------------------------------------------------------------------------
echo "==> Packaging and deploying agentgateway Helm charts..."
make -C "${CONTROLLER_DIR}" deploy-agentgateway \
    VERSION="${VERSION}" \
    CLUSTER_NAME="${CLUSTER_NAME}" \
    INSTALL_NAMESPACE="${INSTALL_NAMESPACE}" \
    IMAGE_REGISTRY="${IMAGE_REGISTRY}"

#---------------------------------------------------------------------------
# 7. Wait for the controller to be ready
#---------------------------------------------------------------------------
echo "==> Waiting for controller pod to be ready..."
kubectl rollout status deployment/agentgateway -n "${INSTALL_NAMESPACE}" --timeout=120s

#---------------------------------------------------------------------------
# 8. Create a Gateway resource
#---------------------------------------------------------------------------
echo "==> Creating Gateway 'agentgateway-proxy'..."
kubectl apply -f- <<EOF
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: agentgateway-proxy
  namespace: ${INSTALL_NAMESPACE}
spec:
  gatewayClassName: agentgateway
  listeners:
  - protocol: HTTP
    port: 80
    name: http
    allowedRoutes:
      namespaces:
        from: All
EOF

#---------------------------------------------------------------------------
# 9. Verify
#---------------------------------------------------------------------------
echo "==> Waiting for proxy deployment..."
for i in $(seq 1 30); do
    if kubectl get deployment agentgateway-proxy -n "${INSTALL_NAMESPACE}" &>/dev/null; then
        kubectl rollout status deployment/agentgateway-proxy -n "${INSTALL_NAMESPACE}" --timeout=120s
        break
    fi
    echo "    Waiting for proxy deployment to appear... (${i}/30)"
    sleep 5
done

echo ""
echo "==> Installation complete! Cluster state:"
kubectl get pods -n "${INSTALL_NAMESPACE}"
echo ""
kubectl get gateway -n "${INSTALL_NAMESPACE}"
echo ""
echo "To port-forward the proxy for local testing:"
echo "  kubectl port-forward -n ${INSTALL_NAMESPACE} svc/agentgateway-proxy 8080:80"
