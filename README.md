# bongsu-scanner

The `bscan` binary is a self-contained Go scanner that creates SPDX 2.3 and
CycloneDX 1.6 SBOMs from a host filesystem, directory, tar/tgz archive,
Docker image/container, or OCI image archive. It also creates SHA-256
manifests, timestamp-bound Ed25519 signatures, verifies scan artifacts, and
provides a signed reversible binary scrambler. It can also download and merge
vulnerability advisories and match existing SBOMs against a local offline database.

Author: ziozzang@gmail.com · [Project](https://github.com/ziozzang/bongsu-scanner)

## Install and deploy

Build with Go 1.25 or newer (the checkout selects its toolchain in `go.mod`):

```sh
make build VERSION=0.6.0
./dist/bscan init --signer scanner@example.com
./dist/bscan about
```

SQLite is embedded through the pure-Go `modernc.org/sqlite` driver; no system
SQLite library or `sqlite3` executable is required. Put `dist/bscan` on your PATH
for the examples below. Alternatively, use a verified release archive as shown
in the [deployment guide](deploy/README.md#install-a-release), including
`SHA256SUMS.sig` verification and `sha256sum` checking. That guide also covers
containers, systemd, cron, self-update and air-gapped `db export` / `db import`.

## Configuration and initialization

`bscan init` creates the signing identity. By default configuration is
`~/.bongsu/scaner.yaml`, with `signing.key` (0600) and `signing.pub` alongside it.
`BONGSU_HOME` selects the state directory. `BONGSU_CONFIG` or the global
`--config PATH` selects only the configuration file; default keys and database
remain under `BONGSU_HOME`. See [configuration](docs/configuration.md) for
precedence, UTF-8/BOM/CRLF handling, command defaults and `config init` templates.

## First scan and match

```sh
bscan scan --output ./scan-results /path/to/rootfs
# Download the chosen advisory feeds once, then match locally.
bscan db update
bscan scan --match --report html --output ./scan-results /path/to/rootfs
# Add coverage if needed; plain updates retain the installed selection.
bscan db update --add-ecosystem Ubuntu
bscan db status
```

Scans write both SBOM formats by default; `--match` adds `<base>.findings.json`.
`--report html` adds an HTML report. `--report json` is accepted and uses the
findings file; it does not add `.report.json`. Match/report files are unsigned.
Use [database selection](docs/vulnerability-database.md) to bound downloads and
[scanning](docs/scanning.md) for image, registry, host and batch examples.

`--fail-on HIGH` enables a findings gate: the default exit code is 2, changeable
with global `--findings-exit-code N` (1..125, before the command). With defaults,
exit code 2 takes precedence over an LLM enrichment error (exit code 1).
Partial scans with `--fail-on-partial` return 3 before writing an SBOM; cancellation
returns 130. See [exit handling](docs/ci-integration.md#flag-placement-and-exit-status)
for combined errors and CI examples. Global `--quiet` hides progress while keeping
coverage and other result-affecting alerts; `--memory-limit 512MiB` sets a soft
Go heap target.

## Targets and distributions at a glance

| Area | Support |
| --- | --- |
| Scan targets | Linux host, directories, tar/tgz and Docker/OCI archives, local Docker images/containers, remote `registry://` / `oci://` images. |
| Release platforms | Linux amd64/arm64, macOS amd64/arm64, Windows amd64 archives; FreeBSD is CI cross-build only. Host inventory is Linux-specific. |
| Default OS advisory feeds | Debian, Alpine, Wolfi, Red Hat, Rocky Linux, AlmaLinux. RHEL/UBI use major keys through 9 and major.minor keys from 10 onward. |
| Additional OS feeds | Ubuntu, Chainguard, openSUSE/SUSE; Red Hat CSAF VEX is opt-in. CentOS 8+ is excluded from RHEL matching. |
| Language advisory feeds | npm, PyPI, Go, crates.io, Maven, RubyGems, NuGet, Packagist; RubySec is also enabled by default. |

Inventory support does not guarantee advisory coverage. See the
[current support matrix](docs/support-matrix.md) for release mapping, ownership
fallback and limitations. No findings is not proof of no vulnerabilities.

## Security summary

- Pin trusted public keys for provenance; an embedded key alone proves
  consistency, not identity. Version 2 signatures bind signer and target;
  Version 1 leaves those fields unauthenticated. The updater labels v1 signers
  `(unauthenticated: v1 record)`.
- For self-update, a pinned release key requires a valid `SHA256SUMS.sig`,
  even without `--require-signature`. Publishing signatures requires a configured
  key; maintainers use `make release-sign` after generating checksums.
- See [configuration](docs/configuration.md) for `signature_min_version`,
  `update_require_signature`, `db_require_signature` and offline mode.
  `BONGSU_OFFLINE=1` disables network updates, registry pulls and LLM calls.
- Host scans skip virtual/transient `/proc`, `/sys`, `/dev`, `/run`, `/tmp`,
  `/mnt`, and `/media`. The [scrambler](docs/signing.md#scrambler) is reversible
  with the public key and does not provide confidentiality.
- SHA256SUMS protects transfer integrity; GitHub account/release security remains
  part of the update trust boundary. See [signing](docs/signing.md) and
  [publisher policy](docs/releasing.md).

## Documentation

Start with the [documentation index](docs/README.md) or the
[generated command reference](docs/commands.md). Focused guides cover
[matching and reports](docs/matching.md), [LLM review](docs/llm-review.md),
[release maintenance](docs/releasing.md), and the [roadmap](docs/roadmap.md).
See [CHANGELOG](CHANGELOG.md) for changes.

License: [MIT](LICENSE). Embedded dependency licenses are reproduced in
[THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt).
