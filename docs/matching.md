# Matching and reports

```sh
# Scan, then match locally. Matching never downloads advisory feeds.
bscan scan --output results docker://alpine:3.20
bscan match results/alpine_3.20.cdx.json
bscan match --format json -o findings.json results/alpine_3.20.spdx.json
bscan match --format cyclonedx -o enriched.cdx.json results/alpine_3.20.cdx.json

# CI: 0 = completed, 1 = execution error, default 2 = findings threshold.
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
the findings exit code (default 2) takes precedence over an LLM enrichment error
(exit code 1). Set global `--findings-exit-code N` (1..125) before the command.
Cancellation returns 130; a rejected partial scan returns 3 before SBOM output.
See [CI exit handling](ci-integration.md#flag-placement-and-exit-status).
The findings report is retained and the LLM error is still reported. Without a
threshold match, an LLM enrichment error returns exit code 1.

## Severity and release mapping

Matching accepts CycloneDX and SPDX JSON, respects OS release and upstream
source-package identity, evaluates ecosystem version ranges and explicit
versions, and groups unambiguous CVE aliases per component. Records with multiple
distinct CVE aliases retain their original advisory IDs. Use `--min-severity LEVEL`,
`--ignore ID,...`, `--exclude-unimportant`, and `--only-fixed` to filter results.
The default `--severity-source distro` uses the vendor/distribution rating first,
with CVSS as the fallback. Vendor urgency maps as follows: `unimportant` →
`NEGLIGIBLE`, `low` → `LOW`, `medium` → `MEDIUM`, `high` → `HIGH`, and
`emergency`/`critical` → `CRITICAL`. Empty, `not yet assigned`, `end-of-life`,
and other unranked values fall back to CVSS.
Unimportant advisories are included by default. Use `--exclude-unimportant`
to hide them; `--include-unimportant` remains accepted as a deprecated no-op
and prints a one-line notice (including when set to `false`).
With `--severity-source cvss`, `severity` uses the CVSS rating while
`distro_severity` retains the vendor urgency, including `unimportant`.
`--severity-source max` selects the higher rating. Both `--min-severity` and
`--fail-on` use the selected policy's `severity`. Tables and report legends
identify the policy; the default is
`Severity policy: distro (vendor rating first, CVSS fallback)`.
These defaults and options also apply to `scan --match` and `batch --match`.

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

See [severity policy](severity-policy.md), [findings JSON](findings-json.md),
[CI integration](ci-integration.md), and the [support matrix](support-matrix.md).
