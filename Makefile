.PHONY: all build build-all test clean fmt vet cross release dist
.PHONY: lab-up lab-down lab-shell lab-run lab-serve

BINARY=hostveil
VERSION?=$(shell git describe --tags --dirty 2>/dev/null || echo "dev")
DIST_DIR=dist

all: fmt vet build

build:
	go build -o $(BINARY) ./cmd/hostveil/

build-all: build cross

test:
	go test -race -count=1 ./...

fmt:
	gofmt -l . || true

vet:
	go vet ./...

clean:
	rm -f $(BINARY) $(BINARY)-linux-* $(BINARY)-darwin-*
	rm -rf $(DIST_DIR)
	go clean

cross:
	GOOS=linux GOARCH=amd64 go build -o $(BINARY)-linux-amd64 ./cmd/hostveil/
	GOOS=linux GOARCH=arm64 go build -o $(BINARY)-linux-arm64 ./cmd/hostveil/
	GOOS=darwin GOARCH=amd64 go build -o $(BINARY)-darwin-amd64 ./cmd/hostveil/
	GOOS=darwin GOARCH=arm64 go build -o $(BINARY)-darwin-arm64 ./cmd/hostveil/

dist: build-all
	@mkdir -p $(DIST_DIR)
	@for bin in $(BINARY)-linux-amd64 $(BINARY)-linux-arm64 \
		$(BINARY)-darwin-amd64 $(BINARY)-darwin-arm64; do \
		if [ -f "$$bin" ]; then \
			plat=$$(echo "$$bin" | sed 's/^$(BINARY)-//'); \
			archive="$(DIST_DIR)/$(BINARY)-$(VERSION)-$$plat.tar.gz"; \
			tar czf "$$archive" --transform="s|.*|$(BINARY)|" "$$bin"; \
			sha256sum "$$archive" | awk '{print $$1}' > "$$archive.sha256"; \
			echo "  -> $$archive"; \
		fi; \
	done
	@echo "--- dist artifacts ---"
	@ls -lh $(DIST_DIR)/

release:
	@test -n "$(VERSION)" || (echo "VERSION required: make release VERSION=v1.0.0"; exit 1)
	make dist
	git tag -a "$(VERSION)" -m "Release $(VERSION)"
	git push origin "$(VERSION)"
	@echo ""
	@echo "Release $(VERSION) tagged and pushed."
	@echo "Upload dist/*.tar.gz and dist/*.sha256 to GitHub Releases."

# Docker lab shortcuts
lab-up:
	./scripts/lab.sh up

lab-down:
	./scripts/lab.sh down

lab-shell:
	./scripts/lab.sh shell

lab-run:
	./scripts/lab.sh run

lab-serve:
	./scripts/lab.sh serve
