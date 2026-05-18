.PHONY: all build test clean fmt vet

BINARY=hostveil

all: fmt vet build

build:
	go build -o $(BINARY) ./cmd/hostveil/

test:
	go test -race ./...

fmt:
	go fmt ./...

vet:
	go vet ./...

clean:
	rm -f $(BINARY)
	go clean

cross-linux-amd64:
	GOOS=linux GOARCH=amd64 go build -o $(BINARY)-linux-amd64 ./cmd/hostveil/

cross-linux-arm64:
	GOOS=linux GOARCH=arm64 go build -o $(BINARY)-linux-arm64 ./cmd/hostveil/
