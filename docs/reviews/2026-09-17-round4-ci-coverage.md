# Round 4 — CI, one-shot scanning, coverage gaps, test speed — 2026-09-17

Automated engineering jobs (J1–J7, K1–K2) under one coordinating agent; every
change carries regression tests and was verified on the same Debian 13 host
and a 393k-record catalog (OSV Alpine/npm/PyPI/Go/Debian/crates.io/Maven/
RubyGems, Alpine secdb, Debian tracker).

## Added

- GitHub Actions: `ci.yml` (gofmt, vet, `-short -race`, nightly full race,
  linux/amd64+arm64 builds, `go mod verify`, govulncheck) and `release.yml`
  (tag builds, SHA256SUMS, optional signing with `BONGSU_RELEASE_KEY`,
  licenses attached). Makefile `test-short` and `ci`.
- `bscan scan --match [--report html,sarif,...] [--fail-on LEVEL]` runs the
  matcher and report renderers right after the scan, per host and per
  container result. One-shot on this host: 17 s for SBOM + findings + HTML +
  SARIF.
- Ubuntu: OSV `Ubuntu:24.04:LTS` / `Ubuntu:Pro:…` releases and os-release
  codenames normalize to the numeric release; verified on ubuntu:24.04 and
  ubuntu:noble-20240429 against api.osv.dev.
- Java archives (jar/war/ear, nested), installed npm packages without a
  lockfile, Ruby gemspecs; manifest-only jars derive Maven coordinates from
  the archive name, vendor id and package prefixes, or fall back to
  `pkg:generic` so they cannot produce false Maven matches; `Package.Evidence`
  (`bscan:evidence`) records how each package was identified. tomcat:10.1
  now yields `pkg:maven/org.apache.tomcat/tomcat-catalina@10.1.60`; the host
  SBOM gained 1,063 Maven/gem/generic packages and 127 Maven findings.

## Performance and tests

| Item | Before | After |
|---|---:|---:|
| `matcher.LoadFile` on a 53k-component SBOM | 300 MiB | 73 MiB |
| `bscan match --format table` peak RSS | 555 MiB | 292 MiB |
| `go test -short -race ./...` | 103 s | 17 s |
| `go test -race ./...` (full) | ~250 s | 33 s |
| `internal/vulndb` tests | 101 s | 12 s |
| `internal/scan` tests | 69 s | 6 s |

Heavy fixtures were replaced by injectable limits and clocks; production-size
checks remain behind `BSCAN_HEAVY_TESTS=1`.

## Remaining

- `match` RSS ~290 MiB is now dominated by record decoding for packages with
  tens of thousands of advisories.
- `selfupdate.ReleasePublicKey` is still empty; set it to the public half of
  the release signing key before enabling signed self-updates.
- JRE `release` files on plain filesystems are not yet inventoried (only
  inside archives); gem directories without `specifications/` are skipped.
