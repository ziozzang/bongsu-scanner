VERSION ?= 0.1.0
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test release clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/bscan ./cmd/bscan

test:
	go test -race ./...
	go vet ./...

release: clean
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/bscan_$(VERSION)_linux_x86_64 ./cmd/bscan
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/bscan_$(VERSION)_linux_arm64 ./cmd/bscan
	cd dist && sha256sum bscan_$(VERSION)_linux_x86_64 bscan_$(VERSION)_linux_arm64 > SHA256SUMS

clean:
	rm -f dist/bscan dist/bscan_* dist/bongsu dist/bongsu_* dist/SHA256SUMS
