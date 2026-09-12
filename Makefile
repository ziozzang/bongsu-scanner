VERSION ?= 0.1.0
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test release release-sign clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/bscan ./cmd/bscan

test:
	@files="$$(gofmt -l .)" || exit 1; if [ -n "$$files" ]; then printf 'gofmt required:\n%s\n' "$$files"; exit 1; fi
	go test -race -count=1 ./...
	go vet ./...

release: dist/SHA256SUMS

# Explicit releases rebuild; signing an existing release preserves its artifacts.
ifneq ($(filter release,$(MAKECMDGOALS)),)
dist/SHA256SUMS: clean
endif

dist/SHA256SUMS:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/bscan_$(VERSION)_linux_x86_64 ./cmd/bscan
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/bscan_$(VERSION)_linux_arm64 ./cmd/bscan
	cd dist && sha256sum bscan_$(VERSION)_linux_x86_64 bscan_$(VERSION)_linux_arm64 > SHA256SUMS
	cp LICENSE THIRD_PARTY_NOTICES.txt dist/
	@if [ ! -f dist/SHA256SUMS.sig ]; then echo 'Release unsigned: run BONGSU_HOME=/path/to/release-identity make release-sign before publishing.'; fi

# BONGSU_HOME selects the initialized publisher identity (default: ~/.bongsu).
release-sign: dist/SHA256SUMS
	$(MAKE) build
	./dist/bscan sign -o dist/SHA256SUMS.sig dist/SHA256SUMS

clean:
	rm -f dist/bscan dist/bscan_* dist/bongsu dist/bongsu_* dist/SHA256SUMS dist/SHA256SUMS.sig
