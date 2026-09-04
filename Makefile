.PHONY: build docker test lint generate setup-hooks setup-native run clean

BINARY := trust-gateway
GO := go
GOFLAGS := -race -count=1
COVERAGE_MIN := 95

define with-native
	lib_dir="$$(.scripts/ci/setup-cleverbase-ffi.sh)" && \
	CGO_LDFLAGS="$${CGO_LDFLAGS:+$${CGO_LDFLAGS} }-L$${lib_dir}" $(1)
endef

build:
	mkdir -p bin/
	$(call with-native,$(GO) build -o bin/$(BINARY) ./cmd/server/)

docker:
	docker build -t alkemio/trust-gateway:latest .

test:
	$(call with-native,$(GO) test $(GOFLAGS) -coverprofile=coverage.out -covermode=atomic ./...)
	@total="$$( $(GO) tool cover -func=coverage.out | awk '/^total:/ {gsub(/%/, "", $$3); print $$3}' )"; \
		echo "coverage: $${total}%"; \
		awk "BEGIN { exit !($${total} >= $(COVERAGE_MIN)) }" || \
		{ echo "coverage $${total}% is below $(COVERAGE_MIN)%"; exit 1; }

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
