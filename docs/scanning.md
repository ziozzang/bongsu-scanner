# Scanning and inventory

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

# Scan, match the local catalog, and report in one command (default findings exit 2 for HIGH+)
bscan scan --match --report html,sarif --fail-on HIGH --output ./scan-results .
```

`--match` writes `<base>.findings.json` next to each result's SBOMs, using
CycloneDX when both formats are written (SPDX for `--format spdx`).
`--report html,markdown,csv,sarif` requires `--match` and writes
`<base>.report.html`, `.report.md`, `.report.csv`, and `.report.sarif`.
`--report json` is also accepted: JSON is already written as
`<base>.findings.json`, so it does not create `<base>.report.json`.
The local catalog must already exist; otherwise the command stops before
scanning and asks you to run `bscan db update`. Use `--db DIR` and
`--db-isolation auto|copy|none` to select the catalog and reader isolation.
`--min-severity`, `--only-fixed`, and `--exclude-unimportant` use the same
filters as `match`; `--fail-on LEVEL` returns the findings exit code (default 2)
when the filtered findings meet the threshold, after results have been written.
Change it with global `--findings-exit-code N` (1..125) before `scan` or `batch`.
Partial-walk rejection returns 3 before SBOM output; cancellation returns 130.
See [CI exit handling](ci-integration.md#flag-placement-and-exit-status) for precedence.
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

Scan directly without Docker with `bscan scan registry://docker.io/library/alpine:3.20`
(alias `oci://`); digest references such as `registry://ghcr.io/org/img@sha256:...`
are also supported. `--platform os/arch[/variant]` selects the image (default
`linux/<GOARCH>`). Registry authentication uses anonymous Bearer tokens or
`BSCAN_REGISTRY_USER`/`BSCAN_REGISTRY_PASSWORD`, falling back to base64 `auths`
entries in `~/.docker/config.json`. Downloads require HTTPS; `--insecure-registry`
permits HTTP only for `localhost` and `127.0.0.1`. Every downloaded blob is checked
against its SHA-256 and descriptor size, including when `--allow-digest-mismatch`
is set. Downloads have 8 GiB total and per-blob defaults (injectable through Go
scan options), a five-minute timeout per request, and three retries with backoff
for HTTP 429/5xx. Temporary OCI data uses `TMPDIR` and is removed on completion,
error, or cancellation; choose a disk with space for the layout and its tar copy.

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
RHEL and UBI match Red Hat mainline errata by major version through RHEL 9
(for example, 9.4 maps to 9), and by major.minor for RHEL 10 and later (10.0
and 10.1 stay separate). RHEL 10+ hosts without a minor version are skipped
with `release-unknown`. CentOS Linux 7 and earlier match by major version.
CentOS 8 and later are excluded with `centos-stream-unsupported`: Stream builds run ahead of RHEL and
use different release strings. Red Hat extended-lifecycle streams (EUS, E4S,
AUS, TUS, ELS, EUS long life, and enterprise_linux_eus) remain in the catalog
under separate product/minor-version keys. They do not match ordinary hosts;
fixed builds such as `*.el9_4` are not comparable with mainline builds and
would cause false positives. Original OSV ecosystem names remain visible.
RPM MODULARITYLABEL is preserved in SBOMs; affected entries with `.module+`
versions match only labelled RPMs, and non-module entries match only unlabelled
RPMs. Red Hat OSV does not identify module names/streams, so this separates
module from non-module builds without distinguishing individual module streams.
RPM/dpkg/APK-owned Python, npm and Ruby metadata stays in the SBOM with `bscan:owner`
(CycloneDX) or `owner=` in the SPDX package comment; language advisory matching
skips these subjects as `distro-owned` when the owning OS package is present in
the same SBOM and matchable, and otherwise matches them normally while counting
`owner-unmatched` (a partial SBOM or an unsupported distribution).
Ownership retains only metadata paths, capped at 65,536 paths and 16 MiB of
path/owner text per scan (also bounded per RPM/APK package); incomplete or
conflicting ownership keeps language matching enabled.

## Batch

```sh
bscan batch --jobs 4 --sign image-a.tar docker://alpine:3.20 ./rootfs
```
