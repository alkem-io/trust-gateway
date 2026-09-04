.PHONY: build docker test lint generate setup-hooks run clean

BINARY := trust-gateway
GO := go
GOFLAGS := -race -count=1
COVERAGE_MIN := 95

build:
	mkdir -p bin/
	$(GO) build -o bin/$(BINARY) ./cmd/server/

docker:
	docker build -t alkemio/trust-gateway:latest .

test:
	$(GO) test $(GOFLAGS) -coverprofile=coverage.out -covermode=atomic ./internal/...
	@total="$$( $(GO) tool cover -func=coverage.out | awk '/^total:/ {gsub(/%/, "", $$3); print $$3}' )"; \
		echo "coverage: $${total}%"; \
		awk "BEGIN { exit !($${total} >= $(COVERAGE_MIN)) }" || \
		{ echo "coverage $${total}% is below $(COVERAGE_MIN)%"; exit 1; }

lint:
	golangci-lint run

generate:
	$(GO) generate ./...

setup-hooks:
	git config core.hooksPath .githooks
	@echo "Git hooks configured"

run:
	$(GO) run ./cmd/server/

clean:
	rm -rf bin/ coverage.out
