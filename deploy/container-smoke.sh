#!/bin/sh
# Run after docker build; no network or host catalog needed.
set -eu
image=${1:?usage: sh deploy/container-smoke.sh IMAGE [EXPECTED_VERSION]}
version=$(docker run --rm --network none "$image" version)
printf 'version: %s\n' "$version"
if [ "$#" -gt 1 ]; then
  first_line=$(printf '%s\n' "$version" | head -n 1)
  case "$first_line" in
    "$2"|"bscan $2") ;;
    *) echo "unexpected version: $version" >&2; exit 1 ;;
  esac
fi
fixture=$(mktemp -d "${TMPDIR:-/tmp}/bscan-container-XXXXXX")
trap 'rm -rf "$fixture"' EXIT HUP INT TERM
chmod 755 "$fixture"
mkdir "$fixture/input" "$fixture/reports"
chmod 777 "$fixture/reports"
printf 'module fixture\nrequire example.com/bscan-container-fixture v1.2.3\n' > "$fixture/input/go.mod"
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --mount "type=bind,src=$fixture/input,dst=/input,readonly" \
  --mount "type=bind,src=$fixture/reports,dst=/reports" \
  "$image" scan --no-sign --workers 1 --output /reports /input
test -s "$fixture/reports/input.cdx.json"
test -s "$fixture/reports/input.spdx.json"
grep -q 'bscan-container-fixture' "$fixture/reports/input.cdx.json"
printf 'non-root, read-only container directory scan: OK\n'
