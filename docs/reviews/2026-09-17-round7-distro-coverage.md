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

## Independent review (R6) of 8bae539..765150e

No P1. Four P2 findings fixed in 80cda58 (RHEL 10 minor mixing, RPM epoch,
stale conversion cache, `--add-ecosystem` without the OSV source), plus the
umask issue and CentOS spelling (P3). Left as documented behaviour: `score`
is omitted when no CVSS score exists (a genuine 0.0 is indistinguishable);
old manifests restore only the OSV ecosystem selection.

## Known limits

- Red Hat OSV records carry CVSS only, so RHEL severity is CVSS-derived; Red
  Hat's own Important/Moderate rating would need the CSAF/VEX feed.
- Multi-CVE RPM errata are advisory-level: an installed build older than the
  erratum is reported for every CVE the erratum lists (for example openssl
  3.0.7 on UBI 9.4 against RHSA-2026:1473 / CVE-2025-11187). The finding ID is
  the erratum with the CVEs as related IDs.
- Fedora, Amazon Linux and Oracle Linux have no supported advisory feed; their
  packages are skipped as `unknown-ecosystem`.
- Ubuntu per-release feeds are opt-in (`--add-ecosystem Ubuntu:24.04`); the
  default catalog is already ~670 MB of OSV downloads.

## Accuracy validation (R4)

See `2026-09-17-accuracy-round7.md` (written by the R4 job) for the
ubi9/ubi8/rocky/alma/ubuntu comparison against Trivy and Grype.
