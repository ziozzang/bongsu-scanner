# Round 3 — performance, reports, and remaining features — 2026-09-10

Implementation and profiling were done by automated engineering jobs with
strict per-job file ownership (P1–P6, G1, H1–H5) under one coordinating agent.
All numbers are from the same Debian 13 developer host (5.7M files, non-root)
and the same feed set (OSV Alpine/npm/PyPI/Go/Debian/crates.io, Alpine secdb
v3.20–v3.22, Debian tracker; 393k records).

## Results

| Path | Before this round | After | Change |
|---|---:|---:|---|
| Host scan, warm wall | 82–114 s | 7.9–8.1 s | openat/fstatat with parent-FD reuse (P1), streaming SBOM writer (P4), 8-worker parallel walk (P6) |
| Host scan, peak RSS | 391 MB | 110–157 MB | P4 removed the in-memory document buffers |
| `db update`, cached feeds | 1 m 56 s | 47 s | batched inserts, deferred indexes, parallel feeds and compression (P3) |
| `db update`, peak RSS | 3.9 GB | 0.67 GB | P3 |
| `advisories.sqlite` | 1.48 GB | 0.97 GB | schema v5: versions as one compressed blob per affected, no duplicated details (H4) |
| `match` (52,820 components) | 6.9 s / 849 MB | 4.7–5.3 s / 555 MB | version-parse caches, visitor lookups, zlib reader reuse (P2), verification cache (P5) |
| Catalog open (hash) | 1.18 s | 0.31 s | `.verified` marker keyed by inode/size/mtime/ctime (P5) |
| Findings with UNKNOWN severity | 7,952 | 4,703 | alias-based severity propagation at ingestion (H1) |
| Accuracy check | curl 38 / libexpat1 26 | unchanged | OSV ground truth |

## New capabilities

- Reports: `bscan match --format html|markdown|csv|sarif` and
  `bscan report --from MATCH.json --sbom SBOM --format ...` (G1). Self-contained
  HTML (1.97 MB for 48k findings), GitHub-flavored Markdown, RFC 4180 CSV,
  SARIF 2.1.0, report JSON schema v1.
- RPM databases (rpmdb.sqlite, BerkeleyDB `Packages`, ndb `Packages.db`) for
  hosts, directories and images; `pkg:rpm/<distro>/...` purls; OSV
  Rocky Linux / AlmaLinux / Red Hat / SUSE ecosystems mapped (H2, H5).
  rockylinux:9-minimal: 118 packages, 132 findings across 44 packages.
- zstd-compressed layers and archives via `github.com/klauspost/compress`
  (new dependency, notice added) with the same digest verification and
  decompression budgets (H3).
- NVD 2.0 feeds as an opt-in severity source (`--source nvd --nvd-years`),
  plus CVSS propagation between advisories sharing a CVE with recorded
  provenance (H1).
- `--workers N` for host/directory scans; hidden `--cpuprofile/--memprofile`
  on `scan` and `match`.
- Toolchain pinned to go1.27.1 in go.mod (`go 1.25.0` minimum retained).

## Verification

`gofmt -l .` empty, `go mod verify`, `go vet ./...`,
`go test -race -count=1 ./...` (15 packages), CGO_ENABLED=0 linux/amd64 and
linux/arm64 builds. Output identity was checked after every optimization
(byte-identical SBOM/match output for identical input; (ref, id) finding sets
unchanged).

## Remaining

- `advisories.sqlite` ~0.97 GB; further reduction needs index/encoding changes.
- `match` RSS ~0.55 GB, dominated by packages that return tens of thousands
  of records (Debian `linux`).
- Test suite runtime grew (vulndb ~100 s, scan ~75 s under -race); consider
  `testing.Short` gates for the heavy fixtures.
- Binary is 24 MB unstripped (12–13 MB stripped) with SQLite, x/sys and
  klauspost/compress.
- Work is uncommitted; commit go.mod/go.sum/THIRD_PARTY_NOTICES.txt together
  with the code.
