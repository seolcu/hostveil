.PHONY: build test test-unit test-contract test-integration lint build-noai build-notui build-noweb build-cross verify-noai clean

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo v3.0.0)
COMMIT  ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
BUILT   ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
PKG     := github.com/seolcu/hostveil/internal/version
LDFLAGS := -s -w -X $(PKG).Version=$(VERSION) -X $(PKG).Commit=$(COMMIT) -X $(PKG).Built=$(BUILT)

build:
	./scripts/build.sh

test:
	./scripts/test.sh

test-unit:
	go test ./... -count=1 -timeout=120s

test-contract:
	go test ./tests/contract/... -count=1 -timeout=120s

test-integration:
	HOSTVEIL_INTEGRATION=1 go test ./tests/integration/... -count=1 -timeout=600s

lint:
	golangci-lint run ./...

build-noai:
	go build -tags noai -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o dist/hostveil-noai ./cmd/hostveil
	@strings dist/hostveil-noai | grep -iE 'anthropic|openai|ollama' && { echo "FAIL: noai binary contains AI literals"; exit 1; } || echo "OK: noai binary contains no AI literals"

build-notui:
	go build -tags notui -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o dist/hostveil-notui ./cmd/hostveil

build-noweb:
	go build -tags noweb -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o dist/hostveil-noweb ./cmd/hostveil

build-cross:
	GOOS=linux GOARCH=amd64 ./scripts/build.sh
	GOOS=linux GOARCH=arm64 ./scripts/build.sh
	GOOS=linux GOARCH=386 ./scripts/build.sh || true
	GOOS=linux GOARCH=arm GOARM=7 ./scripts/build.sh || true

verify-noai: build-noai

clean:
	rm -rf dist
