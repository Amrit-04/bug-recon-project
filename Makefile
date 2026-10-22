.PHONY: build test lint run clean release help

# Build the binary
build:
	go build -o scoutr.exe ./cmd/scoutr

# Run tests
test:
	go test -v ./...

# Run tests with race detector (requires cgo)
test-race:
	@echo "Note: -race requires CGO_ENABLED=1"
	CGO_ENABLED=1 go test -race -v ./...

# Lint and format
lint:
	go vet ./...
	gofmt -w -s .

# Check formatting
fmt-check:
	@if [ -n "$$(gofmt -l .)" ]; then \
		echo "Go files must be formatted with gofmt. Run 'make lint' to fix."; \
		gofmt -l .; \
		exit 1; \
	fi

# Run the tool (example)
run:
	./scoutr.exe --help

# Clean build artifacts
clean:
	rm -f scoutr.exe scoutr
	go clean

# Cross-compile for multiple platforms
release:
	@echo "Building for linux/amd64..."
	GOOS=linux GOARCH=amd64 go build -o dist/scoutr-linux-amd64 ./cmd/scoutr
	@echo "Building for darwin/amd64..."
	GOOS=darwin GOARCH=amd64 go build -o dist/scoutr-darwin-amd64 ./cmd/scoutr
	@echo "Building for darwin/arm64..."
	GOOS=darwin GOARCH=arm64 go build -o dist/scoutr-darwin-arm64 ./cmd/scoutr
	@echo "Building for windows/amd64..."
	GOOS=windows GOARCH=amd64 go build -o dist/scoutr-windows-amd64.exe ./cmd/scoutr
	@echo "Done!"

# Show help
help:
	@echo "Available targets:"
	@echo "  build       Build the binary"
	@echo "  test        Run tests"
	@echo "  test-race   Run tests with race detector"
	@echo "  lint        Format code and run vet"
	@echo "  fmt-check   Check if code is formatted"
	@echo "  run         Run the tool"
	@echo "  clean       Remove build artifacts"
	@echo "  release     Cross-compile for linux/mac/windows"
	@echo "  help        Show this help message"
