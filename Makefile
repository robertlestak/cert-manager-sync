
# Makefile for cert-manager-sync
#
# Available targets:
#   test                           - Run Go tests and vulnerability checks
#   helm-docs                      - Generate Helm chart documentation
#   helm-docs-check                - Check if Helm chart documentation is up to date
#   helm-validate-template         - Validate Helm chart templates with kubeconform
#   helm-validate-schema           - Validate Helm chart values against JSON schema
#   helm-validate-custom-values    - Validate custom values file (requires VALUES_FILE)
#   helm-validate-all              - Run comprehensive Helm chart validation
#   helm-update-schema             - Update values.schema.json from values.yaml

.PHONY: test
test:
	@echo "Running tests..."
	@go test -v ./...
	@govulncheck -show verbose ./...

.PHONY: helm-docs
helm-docs:
	@echo "Generating Helm chart documentation..."
	@command -v helm-docs >/dev/null 2>&1 || { echo "helm-docs is required but not installed. Install it with: go install github.com/norwoodj/helm-docs/cmd/helm-docs@latest"; exit 1; }
	@helm-docs --chart-search-root=deploy

.PHONY: helm-docs-check
helm-docs-check:
	@echo "Checking if Helm chart documentation is up to date..."
	@command -v helm-docs >/dev/null 2>&1 || { echo "helm-docs is required but not installed. Install it with: go install github.com/norwoodj/helm-docs/cmd/helm-docs@latest"; exit 1; }
	@helm-docs --chart-search-root=deploy --dry-run

.PHONY: helm-validate-template
helm-validate-template:
	@echo "Validating Helm chart templates..."
	@command -v helm >/dev/null 2>&1 || { echo "helm is required but not installed. Please install Helm."; exit 1; }
	@command -v kubeconform >/dev/null 2>&1 || { echo "kubeconform is required but not installed. Install it with: go install github.com/yannh/kubeconform/cmd/kubeconform@latest"; exit 1; }
	@helm template cert-manager-sync ./deploy/cert-manager-sync | kubeconform -strict -verbose

.PHONY: helm-validate-schema
helm-validate-schema:
	@echo "Validating Helm chart values against JSON schema..."
	@command -v helm >/dev/null 2>&1 || { echo "helm is required but not installed. Please install Helm."; exit 1; }
	@command -v yq >/dev/null 2>&1 || { echo "yq is required but not installed. Install it with: go install github.com/mikefarah/yq/v4@latest"; exit 1; }
	@command -v ajv >/dev/null 2>&1 || { echo "ajv-cli is required but not installed. Install it with: npm install -g ajv-cli"; exit 1; }
	@helm show values ./deploy/cert-manager-sync | yq eval -o=json | ajv validate -s ./deploy/cert-manager-sync/values.schema.json

.PHONY: helm-validate-custom-values
helm-validate-custom-values:
	@echo "Comprehensive validation of custom values file..."
	@if [ -z "$(VALUES_FILE)" ]; then echo "Usage: make helm-validate-custom-values VALUES_FILE=path/to/values.yaml"; exit 1; fi
	@command -v helm >/dev/null 2>&1 || { echo "helm is required but not installed. Please install Helm."; exit 1; }
	@command -v kubeconform >/dev/null 2>&1 || { echo "kubeconform is required but not installed. Install it with: go install github.com/yannh/kubeconform/cmd/kubeconform@latest"; exit 1; }
	@command -v yq >/dev/null 2>&1 || { echo "yq is required but not installed. Install it with: go install github.com/mikefarah/yq/v4@latest"; exit 1; }
	@command -v ajv >/dev/null 2>&1 || { echo "ajv-cli is required but not installed. Install it with: npm install -g ajv-cli"; exit 1; }
	@echo "Validating values schema..."
	@yq eval -o=json $(VALUES_FILE) | ajv validate -s ./deploy/cert-manager-sync/values.schema.json
	@echo "Validating generated templates..."
	@helm template cert-manager-sync ./deploy/cert-manager-sync --values $(VALUES_FILE) | kubeconform -strict -verbose
	@echo "Custom values validation passed!"

.PHONY: helm-validate-all
helm-validate-all: helm-validate-template helm-validate-schema
	@echo "Running comprehensive Helm chart validation..."
	@echo "Note: To validate custom values, run: make helm-validate-custom-values VALUES_FILE=your-values.yaml"

.PHONY: helm-update-schema
helm-update-schema:
	@echo "Generating Helm chart values schema..."
	@command -v helm >/dev/null 2>&1 || { echo "helm is required but not installed. Please install Helm."; exit 1; }
	@helm plugin list | grep -q "schema" || { echo "Installing helm-values-schema-json plugin..."; helm plugin install https://github.com/losisin/helm-values-schema-json; }
	@cd deploy/cert-manager-sync && helm schema -f values.yaml -o values.schema.json
	@echo "Schema updated successfully at deploy/cert-manager-sync/values.schema.json"
