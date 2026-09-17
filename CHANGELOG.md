# Changelog

Notable changes to bongsu-scanner are recorded here, following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Unreleased summarizes work reviewed on 2026-09-10 through 2026-09-18.
Historical entries are grouped by commit date rather than inferred release versions.

## [Unreleased]

### Added

- Opt-in Red Hat CSAF VEX (`--add-source redhat-vex`) adds product-specific fixes
  and status to offline matching, replacing the selected OSV Red Hat feed without
  changing saved choices:
  - Weekly archives with a 256 MiB document cap and bounded conversion.
  - Resumable `changes.csv` deltas, archive/delta freshness in `db status`,
    per-run deletion counts and retained tombstone counts.
  - Source-scoped deletions preserve other feeds; bounded deletion tombstones survive
    archive replacement until a newer document reinstates the CVE or the archive
    omits it. Equal timestamps prefer deletion, then delta, then archive.
  - Product impact and aggregate Red Hat ratings, independent of CVSS vectors.
  - No-fix statuses and version-scoped not-affected suppression retain actionable
    findings without treating every disposition as a fixed release.

- SQLite vulnerability catalog with OSV, Alpine, Debian, opt-in GHSA and NVD
  ingestion; offline lookup, verification, conversion, export and import.
- Local SBOM vulnerability matching, severity thresholds, optional LLM
  applicability review, and HTML, Markdown, CSV, SARIF and JSON reports.
- One-shot `scan --match --report` workflows and Ubuntu release normalization.
- RPM databases, zstd archives/layers, nested Java archives, installed npm
  packages and Ruby gemspec inventory with package identification evidence.
- CI and release workflows, release artifacts signed when a publisher key is
  configured, dependency notices,
  profiling flags, walk workers and lightweight test fixtures.
- CLI build metadata in `version`, `--version` and `about`; global quiet,
  JSON logging and no-color compatibility options; configuration file selection with `--config PATH` / `BONGSU_CONFIG`
  while default keys and database remain under `BONGSU_HOME`; Bash, Zsh and Fish completion and a generated command reference.
- Distribution status in findings: Debian not-affected entries suppress range
  hits, undetermined entries lower confidence, and missing ecosystem/release
  coverage produces warnings.
- RubySec as a default RubyGems advisory source; configurable feed expansion
  limits through `--max-feed-uncompressed`.
- 47 fuzz targets across parsers, feed converters, purl/version code,
  configuration, signatures and archive handling (`make fuzz-smoke`).
- Dockerfile, systemd/cron deployment examples, `make dist`/`image`,
  macOS/Windows release archives, FreeBSD CI cross-builds (no release archive),
  and multi-architecture image publishing.
- Binary runtime classification (python, node, ruby, java, openssl,
  busybox, php, perl, nginx, httpd, redis, postgres, mysql/mariadb, curl,
  sqlite, zlib, glibc, musl, bash) with CPEs; opt-in `--cpe` matching
  against NVD configurations; `registry://` and `oci://` targets that pull
  images without a Docker daemon.
- Configuration defaults for scan, match and database commands; `config init`
  creates a commented template without keys and `config show` prints effective values.
- Global `--findings-exit-code N` (1..125) lets CI distinguish findings from
  operational failures; the default remains 2.
- Global `--memory-limit` / `BSCAN_MEMORY_LIMIT` sets a soft Go heap target.
- Red Hat, Rocky Linux and AlmaLinux feeds in the default catalog; missing
  coverage warnings suggest adding the maintained base ecosystem export.

- Red Hat VEX deletion history survives forced updates and conversion-cache
  rebuilds, is reconciled against document tracking dates (so fresh and
  incremental catalogs agree until upstream prunes deletions.csv), is not
  cleared by malformed or oversized archive documents, is capped at 200,000
  tombstones, and incomplete delta runs warn even under `--quiet`.
- `--config PATH` and `BONGSU_CONFIG` select the configuration file (keys and
  the database stay under `BONGSU_HOME`); `config show` prints the resolved
  path. Development builds report `0.6.0-dev`; Docker packaging tests run only
  with `BSCAN_DOCKER_TESTS=1` (set in CI).

### Changed

- Raise the per-feed download bound to 1 GiB and the feed expansion budget to 32 GiB.
- Show feed freshness as `data through`, separately from download time, and warn
  when the newest record is older than 60 days.

- Persist catalog feed selections across plain `db update` runs and show them
  on the `Selection:` line in `db status`; add repeatable `--add-ecosystem`, `--add-source`, and
  `--add-alpine-release`, default-list expansion, and mapping of frozen release-qualified OSV exports
  to maintained base exports.
- Default matching severity to `distro` (vendor rating first, CVSS fallback)
  and include Debian unimportant / Ubuntu negligible advisories as `NEGLIGIBLE`. Add
  `--exclude-unimportant`; retain `--include-unimportant` as a deprecated
  no-op with a notice. Severity thresholds follow the selected policy, and
  table/report legends describe it across match, scan and batch workflows.
- Reduce memory use for filesystem cataloging, SBOM writing/loading and advisory
  lookup; preserve CVSS enrichment across unambiguous CVE aliases.
- Keep compact findings by default, with `--details` for advisory descriptions.
- Pin the build toolchain to Go 1.27.1 while retaining Go 1.25 as the minimum.
- Replace production-sized test fixtures with injectable limits and clocks;
  retain opt-in heavy tests through `BSCAN_HEAVY_TESTS=1`.
- `db status` folds release-qualified ecosystems into "Name (N releases)";
  `bscan init` no longer pins feed limits in scaner.yaml (defaults stay
  commented out) and `db update` warns when a pinned limit is below the
  current default.
- `db convert` streams catalog conversion to reduce memory use on large databases.
- `--quiet` keeps alerts that change how results must be read (failed feed
  downloads, coverage gaps, unavailable LLM review); progress stays silent.
- Display binary sizes with MiB/GiB units consistently; `scan/batch --match
  --report json` uses the existing findings JSON without a duplicate report file.
- Standardize findings JSON as `bscan-findings/1` with snake_case fields, string PURLs, generation metadata, and schema validation on report import.

### Fixed

- Scope Ubuntu USN aliases and vendor ratings to each affected entry's release
  and CVE set, including ignores, suppression and equal-scope severity merging.
- Use major.minor release keys for RHEL/UBI 10+; retain major keys through 9,
  keep extended-lifecycle streams separate, and exclude CentOS 8+ from RHEL matching.
- Group AlmaLinux errata by related CVE aliases when needed and use vendor
  title ratings so Moderate/Important appear as MEDIUM/HIGH.
- Separate modular/non-modular RPM matching; retain distro-owned language
  inventory and match it normally when its owning OS package is absent or
  unmatchable (`owner-unmatched`).

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
- Preserve Ubuntu CVE aliases across updates, enable implied sources for feed
  additions, compare RPM epochs correctly, and respect umask for new reports
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

Review evidence and historical measurements: [initial review](docs/reviews/2026-09-10.md),
[parser and performance review](docs/reviews/2026-09-10-round2.md),
[feature review](docs/reviews/2026-09-10-round3-performance-and-features.md),
[CI coverage](docs/reviews/2026-09-17-round4-ci-coverage.md),
[acceptance](docs/reviews/2026-09-17-acceptance.md),
[distribution comparison](docs/reviews/2026-09-17-accuracy-round7.md).
Measurements describe their recorded fixtures and commits, not new release benchmarks.

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
