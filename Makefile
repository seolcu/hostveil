.PHONY: all build test clean fmt vet cross release

BINARY=hostveil

all: fmt vet build

build:
	go build -o $(BINARY) ./cmd/hostveil/

test:
	go test -race -count=1 ./...

fmt:
	gofmt -l . || true

vet:
	go vet ./...

clean:
	rm -f $(BINARY)
	go clean

cross:
	GOOS=linux GOARCH=amd64 go build -o $(BINARY)-linux-amd64 ./cmd/hostveil/
	GOOS=linux GOARCH=arm64 go build -o $(BINARY)-linux-arm64 ./cmd/hostveil/
	GOOS=darwin GOARCH=amd64 go build -o $(BINARY)-darwin-amd64 ./cmd/hostveil/
	GOOS=darwin GOARCH=arm64 go build -o $(BINARY)-darwin-arm64 ./cmd/hostveil/

release:
	@test -n "$(VERSION)" || (echo "VERSION required: make release VERSION=v1.0.0"; exit 1)
	git tag -a "$(VERSION)" -m "Release $(VERSION)"
	git push origin "$(VERSION)"
