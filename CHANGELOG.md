# Changelog

Notable changes to bongsu-scanner are recorded here, following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Unreleased summarizes work reviewed on 2026-09-10 through 2026-09-17.
Historical entries are grouped by commit date rather than inferred release versions.

## [Unreleased]

### Added

- SQLite vulnerability catalog with OSV, Alpine, Debian, opt-in GHSA and NVD
  ingestion; offline lookup, verification, conversion, export and import.
- Local SBOM vulnerability matching, severity thresholds, optional LLM
  applicability review, and HTML, Markdown, CSV, SARIF and JSON reports.
- One-shot `scan --match --report` workflows and Ubuntu release normalization.
- RPM databases, zstd archives/layers, nested Java archives, installed npm
  packages and Ruby gemspec inventory with package identification evidence.
- CI and release workflows, signed release artifacts, dependency notices,
  profiling flags, walk workers and lightweight test fixtures.
- CLI build metadata in `version`, `--version` and `about`; global quiet,
  JSON logging and no-color compatibility options; configuration override
  plumbing; Bash, Zsh and Fish completion and a generated command reference.

### Changed

- Stream filesystem cataloging, SBOM serialization and loading, finding output
  and advisory lookups to reduce memory use. Batch database inserts, defer
  indexes, compress records and parallelize feed conversion and host walking.
- Cache verified catalog identities and version parsing; store explicit
  versions compactly and propagate severity across unambiguous CVE aliases.
- Keep compact findings by default, with `--details` for advisory descriptions.
- Pin the build toolchain to Go 1.27.1 while retaining Go 1.25 as the minimum.
- Replace production-sized test fixtures with injectable limits and clocks;
  retain opt-in heavy tests through `BSCAN_HEAVY_TESTS=1`.

### Fixed

- Prioritize OS/package metadata when scanning large hosts; preserve partial
  scan diagnostics and propagate container failures and cancellation.
- Correct OSV limits, distro source-package/release matching, PURL-only
  affected records, package-level severity and ambiguous multi-CVE grouping.
- Correct language lockfile parsing, SPDX fields, CycloneDX identifiers,
  content-derived document identities and deterministic archive handling.
- Handle BOM/CRLF and quoted configuration values, reject malformed security
  settings, report unknown/duplicate keys, avoid batch output collisions and
  return success for help. Correct release-sign ordering and license bundling.
- Preserve severity-threshold exit status when LLM enrichment also fails,
  and preserve existing outputs/databases during interrupted operations.

### Security

- Signature format v2 authenticates signer and target metadata. Retain labelled
  v1 compatibility with configurable `signature_min_version`; require release
  signatures when a release key is pinned.
- Verify isolated catalog snapshots; cover retained raw feeds in new manifests;
  harden recovery, reader cleanup and manifest/signature size checks.
- Bound archive expansion, decompression, downloaded feeds and record fields;
  validate image/config/layer digests, platform selection and filesystem links.
- Prevent symlink-following and mount traversal races in host scanning, sanitize
  feed errors and remove URL query/fragment data before LLM requests.
- Keep original vulnerability findings authoritative during LLM review; reject
  unsupported quotations and preserve unknown or conflicting target context.

Review evidence and historical measurements:
[round 1](docs/reviews/2026-09-10.md),
[round 2](docs/reviews/2026-09-10-round2.md),
[round 3](docs/reviews/2026-09-10-round3-performance-and-features.md),
[round 4](docs/reviews/2026-09-17-round4-ci-coverage.md).
Those measurements describe the review fixtures, not new benchmarks for this CLI change.

## [2026-07-24]

### Added

- Automatic scan signing with a configured identity (`2de24ef`).
- Host paths and trusted signature verification (`9de8d84`).
- Host-metadata SBOM signing without SHA manifests (`cce675d`).

### Changed

- Rename the binary to `bscan` and display scan progress (`d46b7ce`).

## [2026-07-23]

### Added

- Initial bongsu scanner release (`1d9288f`): host/container inventory,
  SPDX/CycloneDX output, artifact hashing/signing, verification and scrambling.

[Unreleased]: https://github.com/ziozzang/bongsu-scanner/compare/2de24ef...HEAD
[2026-07-24]: https://github.com/ziozzang/bongsu-scanner/compare/1d9288f...2de24ef
[2026-07-23]: https://github.com/ziozzang/bongsu-scanner/commit/1d9288f
