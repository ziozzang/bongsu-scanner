VERSION ?= 0.1.0
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test test-short ci release release-sign clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/bscan ./cmd/bscan

test:
	@files="$$(gofmt -l .)" || exit 1; if [ -n "$$files" ]; then printf 'gofmt required:\n%s\n' "$$files"; exit 1; fi
	go test -race -count=1 ./...
	go vet ./...

test-short:
	@files="$$(gofmt -l .)" || exit 1; if [ -n "$$files" ]; then printf 'gofmt required:\n%s\n' "$$files"; exit 1; fi
	go vet ./...
	go test -short -race -count=1 ./...

ci: test-short
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/bscan_$(VERSION)_linux_x86_64 ./cmd/bscan
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/bscan_$(VERSION)_linux_arm64 ./cmd/bscan

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

# Portable archives supplement the existing Linux self-update assets.
.PHONY: image dist
IMAGE ?= ghcr.io/ziozzang/bongsu-scanner
image:
	docker build --platform linux/amd64 --build-arg VERSION="$(VERSION)" -t "$(IMAGE):$(VERSION)" .

dist:
	sh deploy/dist.sh "$(VERSION)"

# Runs every Go fuzz target (*_fuzz_test.go) briefly as a parser robustness
# smoke test. FUZZ_SMOKE_TIME sets the per-target budget.
.PHONY: fuzz-smoke
FUZZ_SMOKE_TIME ?= 5s
fuzz-smoke:
	@set -e; for pkg in $$(go list ./internal/...); do \
	  for target in $$(go test -list '^Fuzz' "$$pkg" 2>/dev/null | grep '^Fuzz'); do \
	    echo "fuzz-smoke: $$pkg $$target"; \
	    go test -run '^$$' -fuzz "^$$target\$$" -fuzztime "$(FUZZ_SMOKE_TIME)" -fuzzminimizetime 100x "$$pkg"; \
	  done; \
	done
