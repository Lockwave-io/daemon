VERSION ?= dev
BINARY  := lockwaved
CMD     := ./cmd/lockwaved
BUILD   := build
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64

.PHONY: build test lint cover build-all clean checksums install vet

## build: Build for current platform
build:
	@mkdir -p $(BUILD)
	go build $(LDFLAGS) -o $(BUILD)/$(BINARY) $(CMD)

## test: Run tests with race detector
test:
	go test -race ./...

## vet: Run go vet
vet:
	go vet ./...

## lint: Run golangci-lint
lint:
	golangci-lint run ./...

## cover: Run tests with coverage report
cover:
	@mkdir -p $(BUILD)
	go test -race -coverprofile=$(BUILD)/coverage.out ./...
	go tool cover -func=$(BUILD)/coverage.out
	@echo "HTML report: go tool cover -html=$(BUILD)/coverage.out"

## build-all: Cross-compile for all target platforms
build-all:
	@mkdir -p $(BUILD)
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; \
		arch=$${platform#*/}; \
		output=$(BUILD)/$(BINARY)-$${os}-$${arch}; \
		echo "Building $${os}/$${arch} -> $${output}"; \
		GOOS=$${os} GOARCH=$${arch} go build $(LDFLAGS) -o $${output} $(CMD); \
	done

## clean: Remove build artifacts
clean:
	rm -rf $(BUILD)

## checksums: Generate SHA-256 checksums for all binaries
checksums: build-all
	@cd $(BUILD) && sha256sum $(BINARY)-* > checksums.txt
	@echo "Checksums written to $(BUILD)/checksums.txt"
	@cat $(BUILD)/checksums.txt

## install: Install to /usr/local/bin
install: build
	install -m 755 $(BUILD)/$(BINARY) /usr/local/bin/$(BINARY)

## help: Show this help
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //' | column -t -s ':'
