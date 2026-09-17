# bongsu-scanner

The `bscan` binary is a self-contained Go scanner that creates SPDX 2.3 and
CycloneDX 1.6 SBOMs from a host filesystem, directory, tar/tgz archive,
Docker image/container, or OCI image archive. It also creates SHA-256
manifests, timestamp-bound Ed25519 signatures, verifies scan artifacts, and
provides a signed reversible binary scrambler. It can also download and merge
vulnerability advisories and match existing SBOMs against a local offline database.

Author: ziozzang@gmail.com

Project: https://github.com/ziozzang/bongsu-scanner

## Command reference

See [the generated command reference](docs/commands.md) for all commands,
flags, defaults, environment variables, configuration keys and exit codes.
Place global logging flags before the command: `bscan --quiet scan .` suppresses
migrated progress logs; `bscan --log-format=json scan .` emits structured progress
and scan summaries on stderr. Errors remain visible. These flags currently cover
main.go scan/batch logging; the reference lists the remaining migration scope.

## Build and initialize

Building requires Go 1.25 or newer. SQLite is embedded through the pure-Go
`modernc.org/sqlite` driver; the resulting binary does not require a system
SQLite library or a `sqlite3` executable.

```sh
make build VERSION=0.5.0
./dist/bscan init --signer ziozzang@gmail.com
./dist/bscan about
```

Configuration and keys are stored at `~/.bongsu/scaner.yaml`,
`~/.bongsu/signing.key` (mode 0600), and `~/.bongsu/signing.pub`.
`BONGSU_HOME` can override the directory.

`scaner.yaml` must use UTF-8; an optional leading UTF-8 BOM is accepted, as
are LF and CRLF line endings. UTF-16, invalid UTF-8, and non-printable characters
in keys are rejected. Double-quoted scalars use Go `strconv.Unquote` escapes;
single-quoted scalars keep backslashes literal and represent a quote with `''`.
Quote keys and values containing `:`, `#`, or quotes when needed.
`trusted_keys` must be an indented, flat block map; inline maps and flow sequences
are rejected there and for scalar settings. The existing `formats: [spdx,
cyclonedx]` list is supported. Unknown keys are ignored with warnings available
to CLI consumers; duplicate keys use the last value and produce a warning.
Malformed security settings cause a configuration error, never a fallback to
defaults.

Security settings (defaults shown):

```yaml
offline: false
db_require_signature: false
update_require_signature: false
signature_min_version: 1
trusted_keys:
  # release: "path/to/publisher.pub"
```

`offline` disables network access. `db_require_signature` exposes the trusted
signature policy for database refresh consumers; `update_require_signature` requires a trusted
release signature even without the update command's `--require-signature` flag.
`signature_min_version` accepts `1` (compatibility default) or `2`; setting it to
`2` rejects v1 records during release signature verification. This minimum does
not itself require a signature: pin a `release` key or enable
`update_require_signature` to require authenticated updates.

### Release

`make test` checks Go formatting, runs uncached race tests, and runs `go vet`.
`make release` builds both Linux architectures and writes `dist/SHA256SUMS`,
then copies `LICENSE` and `THIRD_PARTY_NOTICES.txt` into `dist/`. It removes
any previous checksum signature and prints a reminder to sign before publishing.

Use a persistent publisher identity selected by `BONGSU_HOME`:

```sh
export BONGSU_HOME="$HOME/.bongsu-release"
make build VERSION=0.5.0
# Initialize once; keep this directory and its private key for future releases.
./dist/bscan init --signer publisher@example.com
make release VERSION=0.5.0
make release-sign VERSION=0.5.0
./dist/bscan verify --pubkey "$BONGSU_HOME/signing.pub" dist/SHA256SUMS.sig
```

`release-sign` builds a native `dist/bscan` and runs
`./dist/bscan sign -o dist/SHA256SUMS.sig dist/SHA256SUMS` using that identity.
Publish both versioned binaries, `SHA256SUMS`, `SHA256SUMS.sig`, `LICENSE`, and
`THIRD_PARTY_NOTICES.txt` together. Distribute the publisher's public key through
a trusted channel. Re-run `make release-sign` after regenerating the checksums;
`make clean` also removes `dist/SHA256SUMS.sig`.

For `bscan update`, a pinned release key requires a valid `SHA256SUMS.sig`,
even without `--require-signature`. Pin the publisher with
`bscan key trust release publisher.pub`; a built-in release key also counts
as pinned. Missing or invalid signatures then fail the update. Without a pinned
key, updates warn that the signature is unverified and use checksum validation;
`--require-signature` also rejects this unpinned case. `bscan update --check`
only checks the available version and does not verify release artifacts.

## Install and deploy

Download the archive for your OS and architecture from
[GitHub Releases](https://github.com/ziozzang/bongsu-scanner/releases).
Archives use `bscan_<ver>_<os>_<arch>.tar.gz`, with `amd64` or `arm64`, and
contain the executable, `LICENSE` and `THIRD_PARTY_NOTICES.txt`.
Linux and macOS archives contain `bscan`; Windows archives contain `bscan.exe`.
Host scanning is Linux-specific; directory/archive scans and `db`, `match`,
and `report` are intended for other platforms too. The current Windows build
is blocked by Unix-only helpers in `internal/scan/walk.go`; see the
[deployment notes](deploy/README.md) before building all release archives.

Example for Linux amd64 (select an existing release version):

```sh
set -eu
version=0.5.0
asset="bscan_${version}_linux_amd64.tar.gz"
base="https://github.com/ziozzang/bongsu-scanner/releases/download/v${version}"
curl -fLO "$base/$asset"
curl -fLO "$base/SHA256SUMS"
# If this release publishes a signature, fetch and verify it first.
curl -fLO "$base/SHA256SUMS.sig"
# Use an already trusted bscan and a publisher key obtained independently.
bscan verify --pubkey /path/to/publisher.pub SHA256SUMS.sig
awk -v asset="$asset" '$2 == asset { print; found=1 } END { if (!found) exit 1 }' \
  SHA256SUMS > selected.SHA256SUMS
sha256sum --check selected.SHA256SUMS
tar -xzf "$asset"
sudo install -m 0755 bscan /usr/local/bin/bscan
bscan init --signer host-scanner
```

`SHA256SUMS.sig` is a bscan Ed25519 signature record, not a GPG signature.
For initial signature verification, build a verifier from trusted source or use
an existing trusted installation; do not run the downloaded binary to verify
itself. Signatures are optional on releases unless a publisher key is configured.
If no signature is published, checksums provide transfer integrity only; do not
silently skip a signature required by your deployment policy. On macOS use
`shasum -a 256 -c selected.SHA256SUMS`; on Windows compare
`Get-FileHash -Algorithm SHA256 .\bscan_<ver>_windows_amd64.tar.gz` with the exact
entry in `SHA256SUMS`, then extract with `tar -xzf`.

Build containers with `make image VERSION=0.5.0`, or use the tag image
`ghcr.io/ziozzang/bongsu-scanner:v0.5.0`. The image runs as non-root and accepts
the usual CLI arguments, for example `docker run --rm IMAGE version`.
See [container examples](deploy/README.md#container) for writable report mounts,
read-only host mounts at `/host`, and Docker socket access. `scan /host` treats
the target as a directory: explicitly set `--files=false`, `--one-file-system`,
`--exclude` and `--workers`; it does not enable host policy automatically.

[systemd deployment](deploy/README.md#systemd-linux) provides a daily host scan
with HTML findings in `/var/lib/bscan/reports` and a weekly catalog update,
using a dedicated `bscan` account. A cron example is also provided.
`make dist VERSION=0.5.0` builds the five portable archives; the tag-release
workflow uploads them and publishes a multi-architecture container image.

For an air-gapped catalog, initialize the connected publisher once, then export
the signed database and transfer the archive and separately trusted public key:

```sh
# Connected publisher; retain its initialized signing identity.
bscan init --signer catalog-publisher
bscan db update
bscan db export --pubkey "$HOME/.bongsu/signing.pub" catalog.tar.gz

# Offline machine; publisher.pub comes from a trusted channel.
export BONGSU_OFFLINE=1
bscan db import --pubkey /path/to/publisher.pub catalog.tar.gz
bscan db verify --pubkey /path/to/publisher.pub
bscan scan --match --report html --output ./scan-results /path/to/rootfs
```

If `BONGSU_HOME` is set, use that identity's `signing.pub` on the publisher.
For the systemd deployment, import as user `bscan` with
`BONGSU_HOME=/var/lib/bscan` and enable only `bscan-scan.timer` offline.

## Local scan

The default output format is `both`, so a local scan creates both SPDX and
CycloneDX documents without requiring `--format`:

```sh
# Scan the current directory and write results to ./scan-results
bscan scan --output ./scan-results .

# Print every indexed file and discovered package
bscan scan --verbose --output ./scan-results /path/to/rootfs

# Scan the local host filesystem; reuse the invoking user's signing identity
sudo BONGSU_HOME="$HOME/.bongsu" bscan scan --output ./host-scan host

# Scan, match the local catalog, and report in one command (exit 2 for HIGH+)
bscan scan --match --report html,sarif --fail-on HIGH --output ./scan-results .
```

`--match` writes `<base>.findings.json` next to each result's SBOMs, using
CycloneDX when both formats are written (SPDX for `--format spdx`).
`--report html,markdown,csv,sarif` requires `--match` and writes
`<base>.report.html`, `.report.md`, `.report.csv`, and `.report.sarif`.
The local catalog must already exist; otherwise the command stops before
scanning and asks you to run `bscan db update`. Use `--db DIR` and
`--db-isolation auto|copy|none` to select the catalog and reader isolation.
`--min-severity`, `--only-fixed`, and `--include-unimportant` use the same
filters as `match`; `--fail-on LEVEL` returns exit code 2 when the filtered
findings meet the threshold, after all results have been written.
These flags also work with `batch`. With `host --containers`, the host and
each container receive their own findings and reports. Findings and report
files are **not signed**, even when SBOM signing is enabled.

Normal mode prints each major phase—source detection, filesystem walk or
archive/layer processing, package cataloging, SBOM creation, hashing, and
signing. `--verbose` (or `-v`) additionally prints individual files, archive
entries, and packages.

Host SBOM metadata includes hostname, operating system and kernel, CPU model
and logical CPU count, total RAM, architecture, and non-loopback IP addresses.
When a configured identity is available, each host SBOM is signed directly,
so both its inventory and host metadata are covered by the detached signature.
Host and directory scans
do not create separate `.sha256` files. Host scans also disable per-file
checksums and inventory only package metadata. Package metadata locations retain
absolute host paths such as `/home/foo/app/go.mod` and
`/var/lib/dpkg/status`. The legacy `host://` spelling remains accepted only for
backward compatibility.

Host scan controls include repeatable `--exclude PATH`, `--one-file-system`,
`--max-files N`, `--timeout 30m`, `--no-host-metadata`, and `--redact-ip`.
`--containers` additionally inventories running Docker containers into separate
SBOMs. `--skip-binaries` disables Go executable build-info inspection.
`--no-default-excludes` disables default host path exclusions; mount policies
still apply. Incomplete walks are marked in SBOM metadata; `--fail-on-partial`
rejects them before output is written.

## Image scan, sign, and check

```sh
bscan scan docker://alpine:3.20
bscan scan container://my-running-container
bscan scan --verbose --output results image.tar
bscan scan --format spdx /some/rootfs
bscan check results/image.tar.sha256.sig
bscan check --source image.tar results/image.tar.layers.sha256
```

Docker targets use `docker container inspect` and `docker image save`. Archive
scanning itself is embedded: Docker/OCI manifests, tar/gzip/zstd layers, OCI
whiteouts, package databases, and language manifests are parsed in Go without
calling Syft, Trivy, or another SBOM executable. `--platform linux/arm64`
selects an image from a multi-platform archive. Declared layer digest mismatches
fail by default; `--allow-digest-mismatch` retains the mismatch in metadata.
Metadata links follow the merged filesystem, including targets with arbitrary
file names; hardlinks preserve the original target contents.
Outer archives support gzip, bzip2, and zstd compression; bzip2 layers remain
unsupported. Zstd decoding uses `klauspost/compress` with a maximum 256 MiB
window and the same decompression budgets and layer size limits as gzip.

Embedded catalogers currently cover Debian dpkg, Alpine apk, npm lockfiles
and installed `node_modules/**/package.json` (up to 50,000 per scan), Go modules,
Python requirements/dist-info, Cargo lockfiles, Maven `pom.properties`, Java
archives (`.jar`, `.war`, `.ear`, `.jpi`, `.hpi`, including nested archives),
and Ruby `Gemfile.lock` and installed `specifications/*.gemspec` (including
`specifications/default`). Java archives use Maven metadata, manifest attributes,
or artifact-version filenames; nesting is limited to three levels, with a
512 MiB archive cap and a cumulative 512 MiB decompression budget per archive.

RPM databases (rpmdb.sqlite, BerkeleyDB Packages, ndb Packages.db) are inventoried for Rocky, AlmaLinux, RHEL/CentOS, Fedora, Amazon Linux and SUSE-based hosts and images; purls use pkg:rpm/<distro>/... with arch, distro, epoch and upstream (source RPM) qualifiers.

Output and signing depend on the target:

- `host`, directories, `docker://`, and `container://` write only the requested
  SBOMs. With automatic or explicit signing, each SBOM receives its own
  detached `.sig`.
- Physical tar/tgz image files additionally receive a SHA-256 manifest covering
  the original archive and generated SBOMs, plus a layer digest manifest when
  applicable. With automatic or explicit signing, the main SHA-256 manifest is
  signed.

Signatures cover the exact target digest, UTC signing timestamp, and
time-derived 256-bit random salt.

## Automatic signing

After an identity has been initialized with both a signer label and private
key, every scan signs its normal signing target automatically:

```sh
bscan init --signer scanner-01@example.com
bscan scan --output ./host-scan host
```

The startup log reports `auto-sign enabled` and the configured signer.
Automatic signing requires a non-empty `signer` in
`~/.bongsu/scaner.yaml` and a valid configured/default private key. Use
`--no-sign` for an intentionally unsigned scan. `--sign` remains available to
force signing and initialize a missing default key.

## Signature verification

`verify` validates the Ed25519 signature, the signed target digest, the current
SBOM contents, and a pinned/trusted public key. Multiple signatures can be
verified in one invocation:

```sh
# Verify with this scanner's local public key
bscan verify \
  --pubkey ~/.bongsu/signing.pub \
  host-scan/host.spdx.json.sig \
  host-scan/host.cdx.json.sig

# Or register a remote scanner's key once and verify by trust name
bscan key trust scanner-01 scanner-01.pub
bscan verify --pubkey scanner-01 incoming/*.sig
```

New signatures use Version 2. Its payload has a version-specific domain followed
by the digest, target, signer, UTC signing timestamp, and salt, each prefixed
with its byte length (big-endian uint64). Changing any of these signed values
fails verification. The signer label and target name are authenticated by the
signing key; publisher identity still depends on trusting that key.

Version 1 signatures remain accepted for compatibility. They authenticate only
the digest, UTC signing timestamp, and salt under the v1 domain. Their signer
and target fields are unauthenticated and can be changed without invalidating
the signature. Re-sign legacy artifacts to bind those fields. JSON formatting
and equivalent timestamp encodings are not authenticated in either version.

`verify` fails when a key is not pinned, a signed value was modified, the target
is missing, or the current target digest differs. `check` remains the general
command for SHA manifests and layer manifests as well as signatures.

## Scrambler

```sh
bscan scramble encrypt --chunk-size 4MiB -o payload.bgs payload.bin
bscan scramble decrypt --pubkey ~/.bongsu/signing.pub -o restored.bin payload.bgs
```

This is an authenticated **scrambler, not confidentiality encryption**.
The private key signs the artifact and its public key derives the reversible
byte stream, so anyone with the public key can restore it by design.

## Batch and updates

```sh
bscan batch --jobs 4 --sign image-a.tar docker://alpine:3.20 ./rootfs
bscan update --check
bscan update
```

Interactive commands perform a non-blocking update check at most once every
24 hours. Set `BONGSU_NO_UPDATE_CHECK=1` to disable background version checks.
Set `BONGSU_OFFLINE=1` or `offline: true` in configuration to disable both
explicit network updates and background checks; local scanning and matching
remain available.
Updates download the matching Linux release binary, verify it against the
release `SHA256SUMS`, and atomically replace the current executable.
To require signed release checksums, register the publisher's public key with
`bscan key trust release publisher.pub`, then run `bscan update --require-signature`.
The signature must cover the downloaded `SHA256SUMS` and verify against that key
(or a release key embedded at build time).
For accepted v1 records, the updater labels the signer
`(unauthenticated: v1 record)` because that field is not covered by the signature.
Set `signature_min_version: 2` in `scaner.yaml` to reject these legacy records.

## Vulnerability database and offline matching

Download advisories from Google OSV, Alpine secdb, Debian security tracker,
or the GitHub reviewed advisory database. Sources are converted into one OSV-like
record model, merged by advisory ID, and indexed by ecosystem and package name.
GHSA's repository archive is opt-in because it is large.

```sh
# Select sources and ecosystems explicitly to bound download size.
bscan db update --source osv,alpine --ecosystem npm,PyPI,Go --alpine-release v3.20
bscan db status
bscan db lookup npm lodash
bscan db lookup Alpine:v3.20 openssl

# Scan, then match locally. Matching never downloads advisory feeds.
bscan scan --output results docker://alpine:3.20
bscan match results/alpine_3.20.cdx.json
bscan match --format json -o findings.json results/alpine_3.20.spdx.json
bscan match --format cyclonedx -o enriched.cdx.json results/alpine_3.20.cdx.json

# CI: 0 = completed, 1 = execution error, 2 = severity threshold reached.
bscan match --fail-on HIGH --only-fixed results/alpine_3.20.cdx.json

# Reports: self-contained HTML, Markdown, CSV, or SARIF straight from match ...
bscan match --format html -o report.html results/alpine_3.20.cdx.json
bscan match --format markdown -o report.md results/alpine_3.20.cdx.json
bscan match --format sarif -o findings.sarif results/alpine_3.20.cdx.json

# ... or re-rendered later from a saved JSON result without re-matching.
bscan report --from findings.json --sbom results/alpine_3.20.cdx.json \
  --format html -o report.html --title "alpine:3.20"
```

Report formats carry the target, scan completeness (`partial`, denied and
skipped counts), OS/image metadata from the SBOM, the database revision and
sources, findings sorted by severity with fixed versions and advisory links,
and a per-package rollup. The HTML report is a single file with no external
requests; it sorts, filters, and groups client-side and shows large result sets
in pages. `report --format json` writes report schema version 1; the
`match --format json` document remains the interchange format that
`report --from` reads. SARIF 2.1.0 output maps severities to `error`,
`warning`, and `note` levels with a `security-severity` property so code
scanning services can ingest it.

When the `--fail-on` threshold is met,
exit code 2 takes precedence over an LLM enrichment error (exit code 1).
The findings report is retained and the LLM error is still reported. Without a
threshold match, an LLM enrichment error returns exit code 1.

`db update` with no selections downloads OSV's default ecosystems, Alpine's
configured release list, and Debian tracker. Downloads can be hundreds of MB
per feed. Use `--max-feed-bytes N` to adjust the feed bound, `--timeout 30m` to
bound the operation, `--mirror https://...` for an OSV mirror, and
`--no-keep-raw` to omit original downloads. `--force` bypasses conditional GETs.
Large OSV Ubuntu and Chainguard feeds are opt-in; select their ecosystem names
explicitly and increase the byte limit when needed. The configured byte limit
also applies to GHSA downloads.
NVD is opt-in via `--source nvd`; include it alongside package feeds with `bscan db update --source osv,alpine,debian,nvd --nvd-years 2024-2026`. `--nvd-years` accepts a range or comma-separated list and defaults to the current year and previous two years. Updates fetch yearly and modified NVD feeds. During ingestion, missing CVSS severity may be supplied by another advisory for the same CVE, preferring CVSS V4 over V3 over V2 while preserving existing severity. Provenance is recorded in `database_specific.severity_source` as `alias:<record ID>` or `nvd`.

RubySec is a default source (it is only a few MB); when you pass `--source` explicitly, include `rubysec` to keep it. It downloads [rubysec/ruby-advisory-db](https://github.com/rubysec/ruby-advisory-db)'s master ZIP with ETag conditional requests and a hard 64 MiB cap (a smaller `--max-feed-bytes` is honored). Gem advisories become RubyGems records using a dependency-free YAML subset reader. Numeric `patched_versions` requirements `>= X` map to an ECOSYSTEM range ending at exclusive `fixed: X`, starting at `introduced: 0` or the unaffected boundary; `~> A.B.C` maps to `[A.B.0, A.B.C)`. `unaffected_versions: < X` raises the lower bound to X. With multiple patched branches, the final `>=` range starts after the last earlier patched minor branch, at `A.(B+1).0`, so fixed releases are not reintroduced as vulnerable; duplicate branch fixes use the earliest fix. Complex requirements (including compound constraints, prereleases, and other operators) or missing patch information produce a versions-less affected entry with no ranges and `database_specific.rubysec_unmapped`, allowing the matcher to report `no-usable-range`. CVSS V3/V4 vector strings are retained; numeric scores alone are omitted.

An update builds a complete replacement from the selected feeds; include every
source/ecosystem you want to retain on each update. If any feed fails, the
existing database remains usable and the command returns an error.

The database lives at `$BONGSU_HOME/db` (normally `~/.bongsu/db`). It contains
`advisories.sqlite` (the primary SQLite database), `meta.json`, per-feed parsed
caches, optional raw feeds, and `manifest.sha256`. SQLite tables store records,
package/release associations, aliases, and metadata. Indexed package lookups
read the matching rows without loading an entire ecosystem into memory. Configured signing identities also sign that
manifest. Conditional requests reuse parsed caches when a feed is unchanged.
New manifests include retained raw feeds. Older manifests may omit raw feeds;
those unlisted files are not authenticated by legacy signatures.
One previous generation is retained at `db.prev`.

SQLite schema version 2 is used for new updates. Existing version 1 databases
remain readable and can be converted completely offline:

```sh
bscan db convert --db /path/to/old-db /path/to/sqlite-db
bscan db lookup --db /path/to/sqlite-db npm lodash
# Optional inspection with an external SQLite client:
sqlite3 /path/to/sqlite-db/advisories.sqlite \
  "SELECT id, summary FROM records WHERE id = 'CVE-2026-12345';"
```

The SQLite schema separates fields needed for direct investigation:

| Table | Queryable information |
| --- | --- |
| `records` | ID, source, summary, full bounded description, truncation flag, publication/modification/withdrawal times, first local addition and last observation times |
| `sources`, `record_sources` | Feed name and exact URL, retrieval time, ETag, content hash, byte and record counts, per-record provenance |
| `advisory_references`, `aliases` | Original advisory/reference URLs and related CVE/GHSA identifiers |
| `affected` | Ecosystem, release, package name, PURL, ecosystem-specific and database-specific metadata |
| `affected_ranges`, `range_events` | Comparator family, repository, ordered `introduced`, `fixed`, `last_affected`, and `limit_version` boundaries |
| `affected_versions` | Explicitly enumerated affected versions |
| `severities` | Severity/vector type and raw score/vector |

`records.json` retains the complete normalized record alongside these columns.
Publication/modification timestamps come from upstream; local ingestion timestamps
are separate. Unknown first-added times from legacy databases remain SQL `NULL`.
Exact feed provenance is recorded on new downloads and conditional refreshes;
legacy source URLs are left unknown when they cannot be established.

```sh
bscan db show --db /path/to/sqlite-db GHSA-29mw-wpgm-hmr9
# A CVE alias can also return the associated upstream advisory records.
bscan db show --db /path/to/sqlite-db CVE-2026-12345
```

Conversion preserves the advisory refresh timestamp. A configured local signer
signs the converted database; otherwise it has checksums without a signature.
`--pubkey` pins the source database signer during conversion. Raw downloads
can be omitted with `--no-keep-raw`.

```sh
# Air-gapped transfer. Pin the exporting scanner's public key on import.
bscan db export advisories.tar.gz
bscan db import --pubkey scanner.pub advisories.tar.gz
bscan db verify --pubkey scanner.pub
BONGSU_OFFLINE=1 bscan match --pubkey scanner.pub results/alpine_3.20.cdx.json
```

`--db DIR` selects a different database for any DB subcommand or matching.
Opening a database validates its manifest and any bundled signature. An
unpinned signature proves consistency; `--pubkey` requires a signature from
the selected key. `db verify` also recognizes locally configured/trusted keys.
Unsigned databases can be used with checksum verification.
SQLite readers open a private verified copy so subsequent changes to the source
file cannot alter an active reader. Linux uses copy-on-write cloning when
available; other filesystems require temporary space for a full database copy.
Interrupting catalog import cancels extraction and validation, removes its
temporary staging directory, and preserves the installed database. Catalog
opening and verification also check cancellation during file reads and copying.

Matching accepts CycloneDX and SPDX JSON, respects OS release and upstream
source-package identity, evaluates ecosystem version ranges and explicit
versions, and groups unambiguous CVE aliases per component. Records with multiple
distinct CVE aliases retain their original advisory IDs. Use `--min-severity LEVEL`,
`--ignore ID,...`, `--include-unimportant`, and `--only-fixed` to filter results.
Multiple inputs produce separate table sections or a JSON report array;
CycloneDX output requires one input and adds vulnerability references.
The enriched output is a new artifact and must be signed separately if needed.

Ubuntu matching normalizes distro qualifiers (such as `ubuntu-24.04`), bare
`VERSION_ID` values, and codenames (`bionic`, `focal`, `jammy`, `noble`, `plucky`,
`questing`, `resolute`) to numeric releases. OSV LTS and Pro/ESM advisories match
the same release: `Ubuntu:24.04:LTS` and `Ubuntu:Pro:24.04:LTS` both use `24.04`,
while retaining the original ecosystem for display. FIPS-specific streams
remain separate from ordinary Ubuntu releases.

CVSS v3 and v2 base scores are calculated from their vectors. CVSS v4 vectors
are preserved without estimating a numeric score. Withdrawn advisories, GIT-only
ranges, missing versions, unsupported comparisons, and ecosystems/releases
absent from the installed database are skipped and counted in reports. Matching coverage also
depends on the downloaded feeds and supported version formats. No matches is
not a guarantee that a component has no vulnerabilities.

## Optional LLM applicability review

`match --llm` adds an environmental applicability hypothesis to existing
findings using an OpenAI-compatible Chat Completions endpoint. Configure the
server and model explicitly; no provider or model is selected automatically.
The API key is read from an environment variable, never stored in configuration.

```sh
export BSCAN_LLM_BASE_URL=https://your-llm-server.example/v1
export BSCAN_LLM_MODEL=your-model-name
# Set BSCAN_LLM_API_KEY in your shell/secret manager if the server needs a key.
bscan match --llm --llm-max-findings 20 --format json -o reviewed.json scan.cdx.json

# Supply known deployment facts when the SBOM does not contain them.
bscan match --llm --target-os linux --target-arch amd64 \
  --env-fact windows_compatibility_layer=absent scan.cdx.json
```

Flags `--llm-base-url`, `--llm-model`, and `--llm-key-env` override those settings.
The URL is an API base ending in `/v1` when required by the server; bscan appends
`/chat/completions`. HTTPS is required except for loopback HTTP endpoints such as
`http://127.0.0.1:11434/v1`. A server must support JSON-mode Chat Completions.
No calls are made unless `--llm` is present; `BONGSU_OFFLINE=1` or `offline: true`
disables all LLM requests, including calls to a local HTTP server.

The model receives the matched package/version, advisory summary/description,
and target OS/architecture plus explicitly declared environment facts. SBOM
hostnames, IP addresses, filesystem paths and the whole inventory are excluded.
Reference URLs are context only; bscan does not follow them. Advisory text is
handled as untrusted data, with no model tools or command execution.

Results use `likely_affected`, `likely_not_affected`, or `needs_review` and include
verbatim advisory evidence, preconditions, and checks to perform. For example,
a Windows-only precondition can support `likely_not_affected` on a known Linux
deployment. Missing facts or a truncated description require further review.
Evidence not present in the supplied text is rejected as support for a conclusion.
Verbatim evidence does not prove that the model interpreted it correctly: a
model can quote a real sentence and still draw a contradictory conclusion.
Review the evidence and deployment assumptions before acting on an annotation.
These annotations preserve the original finding, severity and `--fail-on`
behavior; CycloneDX output uses custom properties rather than a definitive VEX
`not_affected` assertion. Request failures retain the findings and write the
report before returning an execution error.

At most 20 distinct findings per input SBOM are reviewed by default. Remaining
findings are marked `not_assessed`; `--llm-max-findings` changes the limit.
Identical inputs reuse cached results keyed by input, model, endpoint and prompt
version. Cache files are private and live under `$BONGSU_HOME/cache/llm`;
`--llm-cache ''` disables caching. `--llm-timeout` bounds each request.

New downloads preserve advisory descriptions up to 64KiB with an explicit
truncation flag. To replace descriptions truncated by the older 2KiB format,
refresh the same selected sources using `db update --force`; a normal 304 refresh
or offline SQLite conversion preserves the existing text.

API protocol reference: [OpenAI Chat Completions](https://developers.openai.com/api/reference/resources/chat).

## Future server submission

A future bongsu server should register each scanner's public-key fingerprint
and accept an upload envelope containing scanner ID, scan ID, target type,
scan/signing timestamps, SBOM files, and detached signatures. The server must
recalculate each SBOM digest and verify it against the registered key before
accepting the scan.

For periodic collection, `bscan` should write completed signed scans to a local
outbox. A systemd timer or cron job can run scans, while a separate submit
worker uploads outbox entries with idempotent scan IDs, retries with backoff,
and deletes or archives an entry only after server acknowledgement. This keeps
scanning functional while the server is offline and avoids giving the scanner
private key to the server.

## Security notes

- Pin a trusted public key with `bscan key trust NAME KEY` and use
  `bscan check --pubkey NAME artifact.sig` for provenance. An embedded key
  alone proves consistency, not identity.
- SHA256SUMS protects update transfer integrity. GitHub account/release
  security remains part of the update trust boundary.
- Host scans skip virtual/transient `/proc`, `/sys`, `/dev`, `/run`, `/tmp`,
  `/mnt`, and `/media`.

License: MIT. Embedded dependency licenses are reproduced in
[THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt).
