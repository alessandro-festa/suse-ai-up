# =============================================================================
# suse-ai-up Makefile
#
# Single primary binary:
#   - manager (Kubernetes operator + HTTP data plane) → cmd/manager
#
# P2.4/PR1 consolidated the HTTP server (formerly cmd/uniproxy) into the
# manager process. Shared targets (test, fmt, vet, lint, manifests, generate)
# operate on the whole module.
# =============================================================================

# ---- Image / version ---------------------------------------------------------
IMG ?= suse-ai-up-manager:latest
ENVTEST_K8S_VERSION = 1.31.0

# ---- Shell / common setup ----------------------------------------------------
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

CONTAINER_TOOL ?= docker

.PHONY: all
all: build

##@ Help

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Manager (operator + HTTP data plane)

.PHONY: build
build: ## Build the consolidated manager binary.
	go build -o suse-ai-up ./cmd/manager

.PHONY: clean
clean: ## Remove built binaries.
	rm -f suse-ai-up
	rm -rf bin/

.PHONY: dev
dev: build ## Build and run the manager locally (needs KUBECONFIG).
	./suse-ai-up

.PHONY: docker-build
docker-build: ## Build the consolidated docker image.
	$(CONTAINER_TOOL) build -t suse-ai-up:latest .

.PHONY: docker-run
docker-run: docker-build ## Build and run the consolidated docker image.
	$(CONTAINER_TOOL) run -p 8911:8911 suse-ai-up:latest

##@ Helm

.PHONY: helm-sync-crds
helm-sync-crds: manifests kustomize ## Regenerate charts/suse-ai-up/crds/crds.yaml from config/crd/.
	@mkdir -p charts/suse-ai-up/crds
	$(KUSTOMIZE) build config/crd > charts/suse-ai-up/crds/crds.yaml
	@echo "Wrote charts/suse-ai-up/crds/crds.yaml ($$(grep -c '^kind: CustomResourceDefinition' charts/suse-ai-up/crds/crds.yaml) CRDs)."

.PHONY: helm-install
helm-install: helm-sync-crds ## Install the suse-ai-up helm chart (CRDs bundled via charts/suse-ai-up/crds/).
	helm install suse-ai-up ./charts/suse-ai-up --namespace suse-ai-up --create-namespace

.PHONY: helm-upgrade
helm-upgrade: helm-sync-crds ## Upgrade the suse-ai-up helm chart. NOTE: Helm does not re-apply CRDs on upgrade — see charts/suse-ai-up/README.md.
	helm upgrade suse-ai-up ./charts/suse-ai-up --namespace suse-ai-up

.PHONY: helm-test
helm-test: helm-upgrade ## Helm-upgrade then print sanity-check commands.
	@echo "Helm chart deployed successfully. In a real Kubernetes environment, you would run:"
	@echo "kubectl wait --for=condition=available --timeout=300s deployment/suse-ai-up-suse-ai-up -n suse-ai-up"
	@echo "kubectl port-forward -n suse-ai-up svc/suse-ai-up-service 8911:8911 &"
	@echo "curl http://localhost:8911/health"
	@echo "curl -H 'X-User-ID: admin' http://localhost:8911/api/v1/adapters"
	@echo "curl -H 'X-User-ID: admin' http://localhost:8911/api/v1/registry"

.PHONY: test-local
test-local: build ## Run the manager locally and smoke-test a few HTTP endpoints.
	@echo "Starting SUSE AI Uniproxy locally..."
	./suse-ai-up &
	@echo "Waiting for service to start..."
	@sleep 10
	@echo "Testing endpoints..."
	curl -f http://localhost:8911/health || echo "Health check failed"
	@echo "Testing admin access..."
	curl -H "X-User-ID: admin" http://localhost:8911/api/v1/adapters || echo "Admin adapter access failed"
	curl -H "X-User-ID: admin" http://localhost:8911/api/v1/users || echo "Admin user access failed"
	curl -H "X-User-ID: admin" http://localhost:8911/api/v1/groups || echo "Admin group access failed"
	@echo "Local testing completed. Press Ctrl+C to stop the service."
	@wait

##@ Quality (whole module)

.PHONY: test
test: ## Run all unit tests across the module.
	go test ./...

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: lint
lint: golangci-lint ## Run golangci-lint linter.
	$(GOLANGCI_LINT) run

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint and apply fixes.
	$(GOLANGCI_LINT) run --fix

##@ Operator — code generation

.PHONY: manifests
manifests: controller-gen ## Generate CRD/RBAC/webhook manifests from API types.
	$(CONTROLLER_GEN) rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases

.PHONY: generate
generate: controller-gen ## Generate DeepCopy methods for API types.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

##@ Operator — build / run

.PHONY: build-manager
build-manager: manifests generate ## Build the manager binary into bin/manager.
	go build -o bin/manager ./cmd/manager

.PHONY: run-manager
run-manager: manifests generate ## Run the manager from your host against ~/.kube/config.
	go run ./cmd/manager

.PHONY: docker-build-manager
docker-build-manager: ## Build the manager docker image.
	$(CONTAINER_TOOL) build -t ${IMG} .

.PHONY: docker-push-manager
docker-push-manager: ## Push the manager docker image.
	$(CONTAINER_TOOL) push ${IMG}

PLATFORMS ?= linux/arm64,linux/amd64
.PHONY: docker-buildx-manager
docker-buildx-manager: ## Build and push the manager image for multiple platforms.
	- $(CONTAINER_TOOL) buildx create --name suse-ai-up-builder
	$(CONTAINER_TOOL) buildx use suse-ai-up-builder
	- $(CONTAINER_TOOL) buildx build --push --platform=$(PLATFORMS) --tag ${IMG} .
	- $(CONTAINER_TOOL) buildx rm suse-ai-up-builder

.PHONY: build-installer
build-installer: manifests generate kustomize ## Generate a consolidated install YAML (CRDs + manager).
	mkdir -p dist
	cd config/manager && $(KUSTOMIZE) edit set image controller=${IMG}
	$(KUSTOMIZE) build config/default > dist/install.yaml

##@ Operator — testing

.PHONY: test-e2e
test-e2e: manifests generate ## Run the e2e tests. Expected an isolated environment using Kind.
	@command -v kind >/dev/null 2>&1 || { echo "Kind is not installed. Please install Kind manually."; exit 1; }
	@kind get clusters | grep -q 'kind' || { echo "No Kind cluster is running. Please start a Kind cluster before running the e2e tests."; exit 1; }
	go test ./test/e2e/ -v -ginkgo.v

##@ Operator — deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: install
install: manifests kustomize ## Install CRDs into the cluster.
	$(KUSTOMIZE) build config/crd | $(KUBECTL) apply -f -

.PHONY: uninstall
uninstall: manifests kustomize ## Uninstall CRDs from the cluster.
	$(KUSTOMIZE) build config/crd | $(KUBECTL) delete --ignore-not-found=$(ignore-not-found) -f -

.PHONY: deploy
deploy: manifests kustomize ## Deploy the manager to the cluster.
	cd config/manager && $(KUSTOMIZE) edit set image controller=${IMG}
	$(KUSTOMIZE) build config/default | $(KUBECTL) apply -f -

.PHONY: undeploy
undeploy: kustomize ## Undeploy the manager from the cluster.
	$(KUSTOMIZE) build config/default | $(KUBECTL) delete --ignore-not-found=$(ignore-not-found) -f -

##@ Dependencies (installed under ./bin)

LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

KUBECTL        ?= kubectl
KUSTOMIZE      ?= $(LOCALBIN)/kustomize
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST        ?= $(LOCALBIN)/setup-envtest
GOLANGCI_LINT  ?= $(LOCALBIN)/golangci-lint

KUSTOMIZE_VERSION        ?= v5.5.0
CONTROLLER_TOOLS_VERSION ?= v0.16.4
ENVTEST_VERSION          ?= release-0.19
GOLANGCI_LINT_VERSION    ?= v1.61.0

.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Install kustomize under ./bin if missing.
$(KUSTOMIZE): $(LOCALBIN)
	$(call go-install-tool,$(KUSTOMIZE),sigs.k8s.io/kustomize/kustomize/v5,$(KUSTOMIZE_VERSION))

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Install controller-gen under ./bin if missing.
$(CONTROLLER_GEN): $(LOCALBIN)
	$(call go-install-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen,$(CONTROLLER_TOOLS_VERSION))

.PHONY: envtest
envtest: $(ENVTEST) ## Install setup-envtest under ./bin if missing.
$(ENVTEST): $(LOCALBIN)
	$(call go-install-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest,$(ENVTEST_VERSION))

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Install golangci-lint under ./bin if missing.
$(GOLANGCI_LINT): $(LOCALBIN)
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))

# go-install-tool: install a Go-based tool into $(LOCALBIN) at a pinned version
# $1 - target path with name of binary
# $2 - package import path
# $3 - version string
define go-install-tool
@[ -f "$(1)-$(3)" ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
rm -f $(1) || true ;\
GOBIN=$(LOCALBIN) go install $${package} ;\
mv $(1) $(1)-$(3) ;\
} ;\
ln -sf $(1)-$(3) $(1)
endef
