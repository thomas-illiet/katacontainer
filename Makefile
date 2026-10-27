.PHONY: generate test test-race coverage build helm-lint helm-template image verify

generate:
	docker build --target build --output type=local,dest=. .

test:
	go test ./internal/...

test-race:
	go test -race ./internal/...

coverage:
	./hack/check-coverage.sh

build:
	docker build -t kata-egress-guard:dev .

helm-lint:
	helm lint charts/kata-egress-guard

helm-template:
	helm template test charts/kata-egress-guard > /dev/null

image:
	docker buildx build --platform linux/amd64,linux/arm64 --provenance=true --sbom=true .

verify: test coverage helm-lint helm-template build
