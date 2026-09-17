#!/bin/sh
set -eu
version=${1:?usage: sh deploy/dist.sh VERSION}
case "$version" in
  ''|*[!0-9A-Za-z.+_-]*) echo 'invalid version' >&2; exit 1 ;;
esac
mkdir -p dist
staging=$(mktemp -d dist/.package-XXXXXX)
trap 'rm -rf "$staging"' EXIT HUP INT TERM
for target in linux/amd64 linux/arm64 darwin/arm64 darwin/amd64 windows/amd64; do
  os=${target%/*}
  arch=${target#*/}
  package="$staging/${os}_${arch}"
  mkdir -p "$package"
  binary=bscan
  if [ "$os" = windows ]; then binary=bscan.exe; fi
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath \
    -ldflags "-s -w -X main.version=$version" -o "$package/$binary" ./cmd/bscan
  cp LICENSE THIRD_PARTY_NOTICES.txt "$package/"
  tar -czf "$staging/bscan_${version}_${os}_${arch}.tar.gz" \
    -C "$package" "$binary" LICENSE THIRD_PARTY_NOTICES.txt
done
# Publish only after every target builds. Never retain a stale signature.
rm -f dist/SHA256SUMS.sig
mv "$staging/"*.tar.gz dist/
(
  cd dist
  set -- bscan_"$version"_*.tar.gz
  # Preserve checksums for legacy Linux assets when built by make release.
  for asset in "bscan_${version}_linux_x86_64" "bscan_${version}_linux_arm64"; do
    if [ -f "$asset" ]; then set -- "$@" "$asset"; fi
  done
  sha256sum "$@" > SHA256SUMS
)
echo 'Archives ready; run make release-sign before publishing signed checksums.'
