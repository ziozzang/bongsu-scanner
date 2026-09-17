# Changelog

Notable changes to bongsu-scanner are recorded here, following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Unreleased summarizes work reviewed on 2026-09-10 through 2026-09-17.
Historical entries are grouped by commit date rather than inferred release versions.

## [Unreleased]

### Added

- Opt-in `redhat-vex` streaming CSAF source with per-CVE RHEL fixes, no-fix
  states, not-affected suppression and vendor severity; supersedes the selected
  OSV Red Hat feed without changing saved source choices.

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
- Distribution status and severity in findings: Debian "not affected"
  entries suppress OSV range hits, "undetermined" lowers confidence,
  `--severity-source cvss|distro|max`, and coverage-gap warnings when an
  ecosystem or release is missing from the catalog.
- `rubysec` (ruby-advisory-db) as a default source with a dependency-free
  YAML subset reader; `--max-feed-uncompressed` so the Ubuntu OSV feed
  installs; conversion cache versioning.
- 45 fuzz targets across parsers, feed converters, purl/version code,
  configuration, signatures and archive handling (`make fuzz-smoke`).
- Dockerfile, systemd/cron deployment examples, `make dist`/`image`,
  darwin/windows/freebsd builds and multi-arch image publishing.
- Binary runtime classification (python, node, ruby, java, openssl,
  busybox, php, perl, nginx, httpd, redis, postgres, mysql/mariadb, curl,
  sqlite, zlib, glibc, musl, bash) with CPEs; opt-in `--cpe` matching
  against NVD configurations; `registry://` and `oci://` targets that pull
  images without a Docker daemon; configuration-file defaults for scan,
  match and db options with `bscan config show|init`.
- Red Hat, Rocky Linux and AlmaLinux OSV feeds in the default catalog. RHEL
  and UBI hosts match mainline errata by major version; EUS/AUS/E4S/TUS
  streams stay out of host matching; CentOS Stream packages are skipped with
  their own reason. Ubuntu vendor priority (`ubuntu_priority`) is the distro
  severity; `negligible` is shown as NEGLIGIBLE and excluded by
  `--exclude-unimportant`; `UBUNTU-CVE-*` records carry their CVE alias.
  Coverage-gap warnings recommend `db update --add-ecosystem` with the
  maintained base Ubuntu export.

### Changed

- Raise the per-feed download bound to 1 GiB; persist and display each feed's
  newest record date and warn on data older than 60 days, including under `--quiet`.

- Persist catalog feed selections across plain `db update` runs and show them
  in `db status`; add repeatable `--add-ecosystem`, `--add-source`, and
  `--add-alpine-release`, default-list expansion, and mapping of frozen release-qualified OSV exports
  to maintained base exports.
- Default matching severity to `distro` (vendor rating first, CVSS fallback)
  and include Debian unimportant advisories as `NEGLIGIBLE`. Add
  `--exclude-unimportant`; retain `--include-unimportant` as a deprecated
  no-op with a notice. Severity thresholds follow the selected policy, and
  table/report legends describe it across match, scan and batch workflows.
- Stream filesystem cataloging, SBOM serialization and loading, finding output
  and advisory lookups to reduce memory use. Batch database inserts, defer
  indexes, compress records and parallelize feed conversion and host walking.
- Cache verified catalog identities and version parsing; store explicit
  versions compactly and propagate severity across unambiguous CVE aliases.
- Keep compact findings by default, with `--details` for advisory descriptions.
- Pin the build toolchain to Go 1.27.1 while retaining Go 1.25 as the minimum.
- Replace production-sized test fixtures with injectable limits and clocks;
  retain opt-in heavy tests through `BSCAN_HEAVY_TESTS=1`.
- `db status` folds release-qualified ecosystems into "Name (N releases)";
  `bscan init` no longer pins feed limits in scaner.yaml (defaults stay
  commented out) and `db update` warns when a pinned limit is below the
  current default. The expansion budget default is 32 GiB.
- `--quiet` keeps alerts that change how results must be read (failed feed
  downloads, coverage gaps, unavailable LLM review); progress stays silent.
- Standardize findings JSON as `bscan-findings/1` with snake_case fields, string PURLs, generation metadata, and schema validation on report import.

### Fixed

- Separate modular/non-modular RPM advisory matching and retain distro-owned
  language inventory with SBOM ownership while skipping upstream matching.

- Prioritize OS/package metadata when scanning large hosts; preserve partial
  scan diagnostics and propagate container failures and cancellation.
- Lockfiles bundled inside installed packages no longer produce phantom
  packages (`--include-declared` keeps them as declared dependencies);
  `package.json` application bundles outside `node_modules` are inventoried;
  OSGi qualifiers are stripped from manifest-derived Maven versions.
- Parser reliability issues found by fuzzing: empty names after namespace
  splitting, quadratic RPM header scans, unvalidated BerkeleyDB lengths,
  unbounded layer references, whiteout cost, purl round trips, and
  normalization idempotence.
- `--fail-on-partial` exits 3; interruption prints one line and exits 130;
  stdout carries only primary results.
- Matching no longer lets an unmatched range's urgency remove other hits;
  rubysec ranges follow bundler-audit semantics; catalog readers detect
  same-tick modifications through the SQLite change counter.
- Registry client hardening (HTTPS for credentials and redirects, no
  server text in errors, sanitized references in logs, manifest cache and
  request budget, Retry-After); classifier requires exact names and
  product markers; CPE attributes normalized consistently.
- Correct OSV limits, distro source-package/release matching, PURL-only
  affected records, package-level severity and ambiguous multi-CVE grouping.
- Correct language lockfile parsing, SPDX fields, CycloneDX identifiers,
  content-derived document identities and deterministic archive handling.
- Handle BOM/CRLF and quoted configuration values, reject malformed security
  settings, report unknown/duplicate keys, avoid batch output collisions and
  return success for help. Correct release-sign ordering and license bundling.
- Preserve severity-threshold exit status when LLM enrichment also fails,
  and preserve existing outputs/databases during interrupted operations.
- Rebuild older conversion caches for Ubuntu CVE aliases, enable implied
  sources for database additions, and respect umask for new findings/reports
  while preserving existing output permissions.

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
