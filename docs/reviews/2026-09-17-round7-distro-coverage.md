# Round 7 — distribution coverage, catalog selection, findings schema (2026-09-17)

Goal: close the gaps a commercial user hits first on RHEL/UBI, Rocky,
AlmaLinux and Ubuntu hosts, make `db update` safe to follow from a warning
and safe to run from cron, and freeze the findings JSON before a first tag.
Work ran as independent codex jobs with strict file ownership, each verified
with `gofmt`, `go vet`, `make lint` and `go test -race ./...` before push.

## What changed

| Area | Before | After | Commit |
|---|---|---|---|
| Red Hat (RHEL, UBI) | Feed opt-in; every package skipped `release-unknown` because `Red Hat:enterprise_linux:9::appstream` never matched a host release | Default feed; mainline keys normalize to the major (`9`) or, for RHEL 10+, `major.minor` (`10.1`); EUS/AUS/E4S/TUS/ELS streams keep their own keys and never match plain hosts; UBI 9.4: 0 → 180 findings, 182 → 0 release-unknown skips | 40ef6b3, 80cda58 |
| Rocky Linux, AlmaLinux | Feed opt-in | Default feeds (5 MB + 6 MB) | 40ef6b3 |
| CentOS | Mapped to Red Hat | CentOS Linux ≤ 7 matches RHEL errata; CentOS Stream 8+ is skipped as `centos-stream-unsupported` (both `centos-9` and `centos-stream-9` spellings, any namespace case) | 40ef6b3, 80cda58 |
| Ubuntu severity | CVSS only; distro column empty | `ecosystem_specific.ubuntu_priority` (export) / `severity[].type=Ubuntu` (API) is the distro rating; `negligible` shows as NEGLIGIBLE and is excluded by `--exclude-unimportant`; `UBUNTU-CVE-*` records carry their CVE alias (conversion cache v4 rebuilds installed catalogs) | 40ef6b3, 80cda58 |
| Coverage warnings | Recommended `--ecosystem X`, which replaced the whole selection | Recommend `db update --add-ecosystem <feed>`, per-release Ubuntu export (`Ubuntu:24.04:LTS`, 142 MB vs 700 MB); warnings survive `--quiet` | 40ef6b3, 36bb586 |
| `db update` selection | Rebuilt from flags only; cron dropped hand-added feeds | Selection persisted in the catalog; plain updates reuse it; `--add-ecosystem/--add-source/--add-alpine-release`, `default` token, implied sources, `Selection:` line in `db status`; rolling NVD years stay rolling | 36bb586, 80cda58 |
| Findings JSON | Mixed Go-name and snake_case keys | `bscan-findings/1`: snake_case, purl strings, `generated_at`, `tool`; `report --from` rejects legacy/unknown schemas; `docs/findings-json.md`, `docs/ci-integration.md` | 36bb586 |
| RPM epoch | Epoch qualifier ignored when the component carried a version (fixed packages reported) | Applied after version selection in both loaders | 80cda58 |
| Output permissions | 0600 (broke container smoke), then chmod 0644 ignoring umask | Created 0644 subject to the umask; existing targets keep their mode | 8bae539, 80cda58 |
| Exit codes / help | `--findings-exit-code` reset before exit (D9); root help missed two flags (D10) | Pinned before global-flag restore, subprocess test; help synced with a registry test | 868414a |
| OSV exports | Per-release exports recommended (frozen since 2024-10) | Release-qualified selections map to the maintained base export; `data through` per source; 60-day staleness warning; feed bound 1 GiB, expansion 32 GiB | cf85cdd, 3024bb2 |
| AlmaLinux | CVEs only in `related`; rating only in the title | CVE aliases promoted for ALSA/ALBA/ALEA; title rating is the distro severity | cf85cdd |
| RPM modules / ownership | Non-modular RPMs matched against module builds; RPM-owned Python matched by upstream version | MODULARITYLABEL and owned metadata paths from headers, dpkg lists and apk db; `module-mismatch` / `distro-owned` skips; `bscan:owner` and `bscan:modularity` properties | 19fbb06, d2077c9 |
| Red Hat unfixed CVEs / ratings | RHSA-only export | Opt-in `redhat-vex` CSAF source: fixed builds, affected / fix-deferred / will-not-fix / under-investigation / out-of-support states, not-affected markers, Red Hat ratings, module streams | 3024bb2, d2077c9 |
| Config template | `init` pinned feed limits, freezing old defaults | Limits commented out in the template; warning when a pinned limit is below the built-in default | 3024bb2 |

## Independent reviews

- **R6** (8bae539..765150e): no P1; four P2 fixed in 80cda58 (RHEL 10 minor
  mixing, RPM epoch, stale conversion cache, `--add-ecosystem` without the
  OSV source) plus umask handling and CentOS spellings.
- **R15** (80cda58..1ddd44d): one P1 — a `not-affected` marker for one
  module stream (nodejs:20) suppressed a real finding for another
  (nodejs:18); P2 — VEX documents were decoded whole before structure
  limits applied, HTTP 304 reuse bypassed a lowered expansion budget,
  language packages were skipped for owners absent from the SBOM, a
  per-binary Red Hat rating was raised by the source-package aggregate,
  ownership lookups were quadratic, and Save() commented out explicit
  limits. All fixed in d2077c9 (token-streaming VEX decoder with hard
  bounds and a 256 MiB document ceiling that keeps the broadest CVEs).

## Accuracy validation

`2026-09-17-accuracy-round7.md` (R4, commit 36bb586) and its "After fixes
(round 7b)" section (R14, commit 1ddd44d): seven pinned images against
Trivy 0.74.0 and Grype 0.118.0.

| Measure | Round 7 | Round 7b |
|---|---|---|
| Inventory agreement (6 supported images) | 857/862 | 857/862 |
| CVE agreement, default catalog + Ubuntu | 767/1,672 | 767/1,672 (stale Ubuntu results replaced: 27 false and 32 missed fixed) |
| CVE agreement with `redhat-vex` on UBI | n/a | 1,655/1,672; 16 of the 17 Trivy-only pairs are Red Hat "Not affected" |
| ubi8 module false positives | 349 CVE pairs | 0 |
| RPM-owned PyPI warnings on UBI | 38 | 0 (55 packages kept in the SBOM with `bscan:owner`) |
| AlmaLinux CVE ids / UNKNOWN ratings | 0 ids in output, 8/8 UNKNOWN | 48 ids, 0 UNKNOWN |
| Severity agreement with Trivy on common UBI CVEs | 158/327 | 685/685 (VEX) |

Still open after 7b (with owners): USN per-release CVE maps and
version-specific VEX not-affected markers (R18), VEX source entries
without module labels (Red Hat data), Ubuntu "Needs evaluation" shown with
high confidence (OSV carries no triage state), advisory-level CVE
propagation for Rocky/Alma errata, weekly VEX archive lag.

## Known limits

- Red Hat's own rating and unfixed states need the opt-in `redhat-vex`
  source (317 MB archive, ~20 GB expanded, 4–8 minutes to convert).
- Multi-CVE RPM errata from the OSV exports are advisory-level: an
  installed build older than the erratum is reported for every CVE the
  erratum lists. VEX replaces this for RHEL; Rocky/Alma keep it.
- Fedora, Amazon Linux and Oracle Linux have no supported advisory feed;
  their packages are skipped as `unknown-ecosystem`.
- OSV per-release exports are frozen (2024-10); Ubuntu needs the 700 MB
  base export (`--add-ecosystem Ubuntu`, opt-in).
