.PHONY: build docker test e2e e2e-live lint generate setup-hooks setup-native run clean

BINARY := trust-gateway
GO := go
GOFLAGS := -race -count=1
COVERAGE_MIN := 95
UNIT_PACKAGES := ./cmd/... ./internal/...

define with-native
	lib_dir="$$(.scripts/ci/setup-cleverbase-ffi.sh)" && \
	CGO_ENABLED=1 CGO_LDFLAGS="$${CGO_LDFLAGS:+$${CGO_LDFLAGS} }-L$${lib_dir}" $(1)
endef

build:
	mkdir -p bin/
	$(call with-native,$(GO) build -o bin/$(BINARY) ./cmd/server/)

docker:
	docker build -t alkemio/trust-gateway:latest .

test:
	@output="$$( $(call with-native,$(GO) test $(GOFLAGS) -coverprofile=coverage.out -covermode=atomic $(UNIT_PACKAGES)) 2>&1 )" || \
		{ status=$$?; printf '%s\n' "$${output}"; exit $$status; }; \
	printf '%s\n' "$${output}"; \
	failures="$$(printf '%s\n' "$${output}" | awk -v min=$(COVERAGE_MIN) ' \
		$$1 == "?" && $$0 ~ /\[no test files\]/ { print $$2 ": no test coverage" } \
		{ for (i = 1; i <= NF; i++) if ($$i == "coverage:") { pct = $$(i + 1); gsub(/%/, "", pct); if (pct + 0 < min) print $$2 ": " pct "%" } }')"; \
	if [ -n "$${failures}" ]; then \
		printf 'package coverage below $(COVERAGE_MIN)%%:\n%s\n' "$${failures}"; \
		exit 1; \
	fi; \
	total="$$( $(GO) tool cover -func=coverage.out | awk '/^total:/ {gsub(/%/, "", $$3); print $$3}' )"; \
	printf 'total coverage: %s%%\n' "$${total}"

e2e: docker
	TRUST_GATEWAY_IMAGE=alkemio/$(BINARY):latest .scripts/e2e/run-mock.sh

e2e-live:
	CGO_ENABLED=0 TRUST_GATEWAY_E2E_MODE=live $(GO) test -v -count=1 ./e2e

lint:
	$(call with-native,golangci-lint run)

generate:
	$(GO) generate ./...

setup-hooks:
	git config core.hooksPath .githooks
	@echo "Git hooks configured"

setup-native:
	@.scripts/ci/setup-cleverbase-ffi.sh

run:
	$(call with-native,$(GO) run ./cmd/server/)

clean:
	rm -rf bin/ coverage.out
