# Version stamped into the binary from the closest git tag (e.g. v0.3.0), with
# -dirty/-<n>-g<sha> suffixes from git describe; falls back to "dev" when the
# tree has no tag yet (the short VCS revision is shown separately either way).
VERSION ?= $(shell git describe --tags --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

.PHONY: build test vet clean

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o teleddns-server ./cmd/teleddns-server

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -f teleddns-server
