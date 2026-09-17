# Findings JSON: bscan-findings/1

`bscan match --format json SBOM.json` writes this interchange document.
`bscan scan --match` and `bscan batch --match` write one
`<base>.findings.json` per scanned target. Multiple inputs to `match` produce
an array of independent documents; split it before using `bscan report --from`.

All schema-defined member names use snake_case. Dictionary keys are data:
severity names remain uppercase, skip reasons retain hyphens, subject properties
retain names such as `bscan:source`, and upstream advisory metadata is preserved.
Unknown future fields may be ignored. Empty optional fields are omitted.
`findings` is always an array, including `[]`; counters are always present.

`bscan report --from findings.json --format html` reads one document of this
version. Missing `schema` produces “legacy findings JSON from a pre-release
build; re-run bscan match”; unknown schema versions are rejected. Renaming old
keys is insufficient: regenerate the findings, including string PURLs.
The `report --format json` presentation envelope (`report_schema_version`) is a
separate format and cannot be used as `--from` input. CycloneDX enrichment keeps
its own standard field names and does not become a findings document.

## Document fields

| Field | JSON type | Meaning / presence |
| --- | --- | --- |
| `schema` | string | Always `bscan-findings/1`. |
| `generated_at` | string | Generation time, RFC3339 UTC (`Z`, optional fractional seconds). Matcher callers may inject `Options.Now` for reproducible tests. |
| `tool` | object | CLI producer: `name` = `bscan`, `version` = build version string. Omitted for library callers without a version. |
| `findings` | array of finding | Retained, deduplicated findings after policy filters; never null. Ordered by severity descending, package name, ID, then subject reference. |
| `subjects` | integer | Input subject count, including non-package SBOM subjects that may be skipped. |
| `matched` | integer | Distinct subject references having at least one retained finding; not the number of findings. |
| `skipped` | object of integer | Reason-to-count dictionary, `{}` when empty. Reasons below count subjects or advisory checks; do not subtract their sum from `subjects`. |
| `by_severity` | object of integer | Finding counts by effective severity. Absent levels mean zero; empty results use `{}`. |
| `db` | object | Catalog metadata; fields below. |
| `missing_coverage` | array of string | Optional coverage-gap warnings and suggested database updates. No warning does not prove complete coverage. |
| `severity_policy` | string | Human-readable policy explanation, emitted by matching. Use `severity` for decisions instead of parsing this text. |

## Finding fields

| Field | JSON type | Meaning / presence |
| --- | --- | --- |
| `id` | string | Canonical advisory ID, preferring an unambiguous CVE alias. |
| `related_ids` | array of string | Optional related/alias IDs; may include `id` itself. |
| `subject` | object | Installed/inventoried component, described below. |
| `record` | object | Compact advisory summary, described below. |
| `affected` | object | The matched OSV-style affected entry, described below. |
| `matched_by` | string | `purl-name`, `binary-name`, `upstream`, or `cpe`. See vocabulary below. |
| `fixed_in` | array of string | Optional known fixed versions for matched intervals. Absence means no known fix; multiple branches need not share one upgrade. |
| `severity` | string | Effective policy-selected level: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NEGLIGIBLE`, `UNKNOWN`. |
| `score` | number | Optional nonzero advisory/CVSS score. Absence can mean unknown or zero; it is not a vendor-adjusted score. |
| `vector` | string | Optional CVSS vector. A vector can be present without a calculated score. |
| `confidence` | string | `high` or `low`, describing matching confidence, independent of severity. |
| `distro_severity` | string | Optional vendor rating, such as critical/high/medium/low, important/moderate, unimportant/negligible, unknown or end-of-life; preserves normalized feed vocabulary. |
| `distro_status` | string | Optional `undetermined`: retained finding requiring review, with low confidence. `not-affected` suppresses a candidate instead of appearing here. |
| `assessment` | object | Optional LLM advisory review; never removes the underlying match or overrides its severity. Fields below. |

Severity order is CRITICAL > HIGH > MEDIUM > LOW > NEGLIGIBLE > UNKNOWN.
`NEGLIGIBLE` includes vendor unimportant/negligible ratings; `UNKNOWN` means no
usable rating. `--severity-source distro` (default) uses the vendor rating then
CVSS fallback; `cvss` uses CVSS; `max` selects the higher level. Filtering and
failure thresholds use the resulting `severity`, not `score`.

`purl-name` matches a package ecosystem/name/version; `binary-name` matches a
distribution binary package; `upstream` matches its source package (using
`upstream_version` when available); `cpe` is opt-in NVD applicability matching.
When equivalent candidates merge, `matched_by` identifies the retained match,
not a list of all evidence. High confidence includes normal version comparisons
and exact CPE matches; low confidence includes uncertain exact-version fallbacks,
non-exact CPE applicability, and vendor `undetermined` status.

## Subject fields

| Field | JSON type | Meaning / presence |
| --- | --- | --- |
| `ref` | string | SBOM component reference, or generated fallback reference. |
| `name` | string | Normalized matching package name. |
| `version` | string | Optional installed version. |
| `purl` | string | Optional canonical Package URL, **not an object**. Namespace, version, qualifiers and subpath round-trip through the parser. |
| `cpe` | string | Optional CPE identifier for CPE matching. |
| `type` | string | Optional PURL type, e.g. `apk`, `deb`, `rpm`, `npm`. |
| `ecosystem` | string | Optional matching ecosystem, e.g. `Alpine`, `Debian`, `npm`. |
| `release` | string | Optional normalized distribution release (e.g. Alpine `v3.20`). |
| `upstream` | string | Optional source package name. |
| `upstream_version` | string | Optional source package version used for matching. |
| `properties` | object of string | Optional SBOM properties, including evidence/source paths; property names are preserved. |

## Advisory, affected entry and assessment

`record.id` and `record.source` are strings, always present. Other record fields
are optional: `aliases` (string array); `summary`, `details` (strings);
`details_truncated` (boolean, present when true); `published`, `modified`,
`withdrawn` (timestamp strings); `severity`, `distro_severity`, `vector` (strings);
`score` (nonzero number); `references` (URL string array). `details` is included
only with `match --details`. The summary does not contain the complete advisory
or every affected package; record severity can differ from policy-selected
finding severity. Withdrawn records are normally excluded by the matcher.

`affected` contains required string `ecosystem` (possibly release-qualified)
and `package`, and optional string `purl`, string-array `versions`, and array
`ranges`. Each range has string `type` (`ECOSYSTEM`, `SEMVER`, or `GIT`), optional
string `repo`, and array `events`. Each event has one string field: `introduced`,
`fixed`, `last_affected`, or `limit`; `introduced: "0"` means all earlier versions.
`ecosystem_specific` and `database_specific` are optional upstream JSON objects;
their internal keys/values are feed-defined. Optional `severity` is an array of
objects with string `type` and `score` (a vector or textual rating, not a number).

`assessment` has string `status` (`likely_affected`, `likely_not_affected`,
`needs_review`, `not_assessed`), string `reason`, string-array `evidence`,
`preconditions`, `checks`, string `model`, string `input_sha256`, and boolean
`cached`. These fields are present when the object exists; arrays may be null
when unavailable. This is advisory analysis, not verified VEX.

## Catalog metadata

`db.schema_version` is the integer **catalog** schema, independent of findings
schema; `updated_at` is an RFC3339 timestamp; `records` is the catalog record
count; `ecosystems` is an array of covered ecosystem strings; `sources` is an
array of source metadata. Library-created reports without catalog data can have
null `sources`/`ecosystems` and a zero timestamp.

Each source has string `name`, string `url`, integer `records`, and timestamp
`fetched_at`. Optional fields are integer `conversion_version`, string-array
`ecosystems`, strings `etag`, `last_modified` (HTTP date), `sha256`, integer
`bytes`, and string `error`. Source counts can overlap across feeds.

Optional `db.selection` records update inputs: string arrays `sources`,
`ecosystems`, `alpine_releases`; string `nvd_years`; boolean `nvd_enabled`.
Selection describes requested feeds, not guaranteed matching coverage.

## Skipped-reason vocabulary

| Reason | Counted when |
| --- | --- |
| `centos-stream-unsupported` | A Red Hat subject identifies CentOS Stream, which is not mapped to RHEL advisories. |
| `unknown-ecosystem` | A subject cannot be assigned a supported ecosystem. |
| `ecosystem-not-in-database` | The subject ecosystem is absent from the catalog. |
| `release-unknown` | Matching needs a distribution release but the subject has none. |
| `release-not-in-database` | The catalog lacks the subject's release. |
| `missing-version` | Neither installed nor upstream version is available. |
| `withdrawn` | An advisory check encounters a withdrawn record. |
| `ignored` | An advisory or alias matches `--ignore`. |
| `distro-not-affected` | A vendor not-affected marker suppresses a positive candidate. |
| `unimportant` | `--exclude-unimportant` removes a vendor unimportant/negligible candidate. |
| `no-usable-range` | Neither usable version ranges nor usable explicit versions establish a match. |
| `cpe-requires-and` | Conservative CPE matching skips a compound AND applicability entry. |

Normal nonmatches, release-mismatched entries, `--only-fixed`, and
`--min-severity` filtering do not necessarily increment a skip reason. CPE
matching is a separate pass, so a subject skipped by ecosystem matching can
still produce a CPE finding. Scan walk omissions are reported in SBOM/report
scan metadata, not added to this matching dictionary.

## Complete example from an offline run

This is actual output from the 6,930-record Alpine v3.20 small catalog at
`BONGSU_HOME=/home/ziozzang/.cache/bongsu-work/home-small`, with
`BONGSU_OFFLINE=1` and `BONGSU_NO_UPDATE_CHECK=1`. The fixture directory `example`
contained `etc/os-release` with `ID=alpine`, `VERSION_ID=3.20.0`, and an APK
installed entry for `bash` `4.4.12-r0`, architecture `x86_64`, source `bash`.
It intentionally represents an old vulnerable package, not a stock Alpine image.

```sh
bscan -q scan --match --report sarif --no-sign --output out .
bscan -q match --format json -o out/rematched.json out/example.cdx.json
bscan -q report --from out/rematched.json --format html -o out/example.html
```

The findings document below is complete (one finding; whitespace pretty-printed).
No severities, counters, timestamps or advisory fields have been invented.
This feed provides fix ranges but no severity for this advisory, hence `UNKNOWN`.

```json
{
  "findings": [
    {
      "id": "CVE-2016-0634",
      "related_ids": [
        "CVE-2016-0634"
      ],
      "subject": {
        "ref": "pkg:apk/alpine/bash@4.4.12-r0?arch=x86_64&distro=alpine-3.20.0",
        "name": "bash",
        "version": "4.4.12-r0",
        "type": "apk",
        "ecosystem": "Alpine",
        "release": "v3.20",
        "upstream": "bash",
        "properties": {
          "bscan:arch": "x86_64",
          "bscan:distro": "alpine-3.20.0",
          "bscan:evidence": "installed",
          "bscan:source": "lib/apk/db/installed",
          "bscan:upstream": "bash"
        },
        "purl": "pkg:apk/alpine/bash@4.4.12-r0?arch=x86_64&distro=alpine-3.20.0"
      },
      "record": {
        "id": "CVE-2016-0634",
        "severity": "UNKNOWN",
        "source": "alpine-secdb"
      },
      "affected": {
        "ecosystem": "Alpine:v3.20",
        "package": "bash",
        "purl": "pkg:apk/alpine/bash?distro=3.20",
        "ranges": [
          {
            "type": "ECOSYSTEM",
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "4.4.12-r1"
              }
            ]
          }
        ],
        "database_specific": {
          "repository": "main"
        }
      },
      "matched_by": "upstream",
      "fixed_in": [
        "4.4.12-r1"
      ],
      "severity": "UNKNOWN",
      "confidence": "high"
    }
  ],
  "schema": "bscan-findings/1",
  "generated_at": "2026-09-17T10:18:21.452875732Z",
  "tool": {
    "name": "bscan",
    "version": "dev"
  },
  "severity_policy": "Severity policy: distro (vendor rating first, CVSS fallback)",
  "subjects": 3,
  "matched": 1,
  "skipped": {
    "unknown-ecosystem": 2
  },
  "by_severity": {
    "UNKNOWN": 1
  },
  "db": {
    "schema_version": 2,
    "updated_at": "2026-09-17T10:01:11.824612697Z",
    "sources": [
      {
        "conversion_version": 3,
        "name": "alpine-secdb",
        "url": "https://secdb.alpinelinux.org/v3.20/main.json",
        "ecosystems": [
          "Alpine:v3.20"
        ],
        "etag": "\"6a571a7b-13d5a\"",
        "last_modified": "Wed, 15 Jul 2026 05:28:27 GMT",
        "sha256": "b09d5fae55c954a23f11b0260ef838726f5045bd3346172feadd39c097ef1c59",
        "bytes": 81242,
        "records": 2798,
        "fetched_at": "2026-09-17T10:01:11.824612697Z"
      },
      {
        "conversion_version": 3,
        "name": "alpine-secdb",
        "url": "https://secdb.alpinelinux.org/v3.20/community.json",
        "ecosystems": [
          "Alpine:v3.20"
        ],
        "etag": "\"69e35c62-202a1\"",
        "last_modified": "Sat, 18 Apr 2026 10:26:42 GMT",
        "sha256": "da5783ab862c06b886e9ea2e5eabeadcda733d7f777e23abfabcd41a164bdbb5",
        "bytes": 131745,
        "records": 4330,
        "fetched_at": "2026-09-17T10:01:11.824612697Z"
      }
    ],
    "ecosystems": [
      "Alpine:v3.20"
    ],
    "records": 6930
  }
}
```
