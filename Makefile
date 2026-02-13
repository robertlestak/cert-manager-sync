
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