VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  = -ldflags "-X main.version=$(VERSION)"

BINARY   = certhound-agent
OUT_DIR  = dist

.PHONY: build build-all test clean

build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/agent

build-all:
	mkdir -p $(OUT_DIR)
	GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -o $(OUT_DIR)/$(BINARY)-linux-amd64   ./cmd/agent
	GOOS=linux   GOARCH=arm64 go build $(LDFLAGS) -o $(OUT_DIR)/$(BINARY)-linux-arm64   ./cmd/agent
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(OUT_DIR)/$(BINARY)-windows-amd64.exe ./cmd/agent

test:
	go test ./...

clean:
	rm -f $(BINARY)
	rm -rf $(OUT_DIR)
