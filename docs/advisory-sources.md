# Advisory sources

See [database selection and updates](vulnerability-database.md) to select feeds,
set download budgets and inspect freshness.

## RubySec

RubySec is a default source; when you pass `--source` explicitly, include `rubysec` to keep it. It downloads [rubysec/ruby-advisory-db](https://github.com/rubysec/ruby-advisory-db)'s master ZIP with ETag conditional requests and a hard 64 MiB cap (a smaller `--max-feed-bytes` is honored).

Gem advisories become RubyGems records using a dependency-free YAML subset reader. Numeric `patched_versions` requirements `>= X` map to an ECOSYSTEM range ending at exclusive `fixed: X`, starting at `introduced: 0` or the unaffected boundary; `~> A.B.C` maps to `[A.B.0, A.B.C)`. `unaffected_versions: < X` raises the lower bound to X. With multiple patched branches, the final `>=` range starts after the last earlier patched minor branch, at `A.(B+1).0`, so fixed releases are not reintroduced as vulnerable; duplicate branch fixes use the earliest fix. Complex requirements (including compound constraints, prereleases, and other operators) or missing patch information produce a versions-less affected entry with no ranges and `database_specific.rubysec_unmapped`, allowing the matcher to report `no-usable-range`. CVSS V3/V4 vector strings are retained; numeric scores alone are omitted.

## Red Hat CSAF VEX

`redhat-vex` is opt-in: `bscan db update --add-source redhat-vex` adds Red Hat’s per-CVE CSAF VEX data; `--source redhat-vex` selects it alone.

A bounded 4 KiB `archive_latest.txt` lookup (30-second deadline) discovers the weekly tar.zst archive; the archive uses conditional GET, `--max-feed-bytes`, and `--max-feed-uncompressed`.

A second feed conditionally fetches `changes.csv` (16 MiB cap) and checks `deletions.csv` (16 MiB cap). It applies post-archive documents over the cached archive, using four HTTPS workers, the 256 MiB per-document cap, a 2 GiB total delta write budget, and at most 20,000 document events per update. Transient document failures get up to three attempts (two retries) with cancellable backoff.

Newer tracking dates replace the VEX contribution rather than unioning stale affected entries; equal instants prefer deletions, then the latest delta, then the archive regardless of timestamp offset spelling. Deletions remove only VEX affected products, provenance and metadata, preserving other sources and their findings; VEX-only deletions retain empty withdrawn stubs that are absent from the package index.

Small CSV/checkpoint and converted delta caches remain with `--no-keep-raw`; each path checkpoints its latest processed event kind and instant, so older events cannot reappear after deletion. A new archive resets changed-document overlays but retains deletion tombstones for CVEs still present with a tracking date older than or equal to the deletion instant; only a strictly newer tracking date reinstates a deleted CVE, and omission from the new archive clears its tombstone. Tombstones are retained up to 200,000 entries; if that bound is exceeded, the
oldest are evicted and a warning reports incomplete deletion history.
Bounded updates report remaining work and resume in event order on the next run without checkpointing events beyond a budget stop.

Malformed paths/documents and oversized documents are counted and skipped until their list timestamp changes. Missing delta documents (HTTP 404) are counted, logged and left pending for retry; a later listed deletion supersedes its older change without downloading the deleted document. A deletion preceding a later change row is retained until the downloaded document has a strictly newer tracking date; if that document returns 404, the deletion is applied and only the change remains pending. Fresh and incremental catalogs use the same tracking-date precedence. A single missing document is non-fatal; two or more missing documents exceeding 10% of attempted document downloads fail the update, as do list download failures. `db status` reports the archive date, applied delta timestamp, document count, skips and remainder. Incomplete updates and missing documents also emit warnings under `--quiet`.

Runtime depends on archive conversion, delta volume and the full SQLite rebuild,
which still runs on 304 updates. Streaming conversion spools each document to disk and decodes it token by token; malformed documents and those over 256 MiB are counted and skipped.

RHEL products include fixed binary RPMs, source-package no-fix states, not-affected markers, vendor ratings, and module metadata; extended lifecycle streams stay separate. When selected alongside OSV, VEX replaces only the OSV Red Hat feed without changing saved choices, so removing VEX restores that feed. Fixed entries use `[0, fixed)` because CSAF does not supply an introduced version; version-specific exclusions stated only in prose are not inferred.

## Measurements

These are historical observations retained from the former README, not release
limits or fresh benchmark results. They have not been independently re-run in
this documentation pass. MiB = 1,048,576 bytes; GiB = 1,073,741,824 bytes.

| Measurement date / recorded commit | Historical observation |
| --- | --- |
| 2026-09-17 / `1ddd44d77fe93f94d97091b0600bd6d6fed80de0` | Ubuntu export 701,433,255 bytes (668.9 MiB); Chainguard 920,476,046 bytes (877.8 MiB). The acceptance record reports default OSV exports totaling 673,371,470 bytes (642.2 MiB), plus other sources. |
| 2026-09-18 / recorded in `24a6de6` (benchmark binary commit not recorded) | Against the 2026-09-13 VEX archive, the former README reported 1,981 documents applied in the first run from a list of 2,154, stopping at the 2 GiB delta budget; a subsequent run applied 181. These are separate run observations: the changes list grew between runs, so 181 is not the arithmetic remainder of the first list. |
| 2026-09-18 / recorded in `24a6de6` (benchmark binary commit not recorded) | Former README timings: about eight minutes for the first run and under three minutes for the subsequent run with archive HTTP 304; memory was reported below 1,000,000,000 bytes (about 954 MiB). Archive expansion was reported as about 19,600,000,000 bytes (18.3 GiB); the broadest document was about 106,000,000 bytes (101.1 MiB). Raw timing/memory evidence was not recorded there. |

See the [distribution comparison](reviews/2026-09-17-accuracy-round7.md),
[recorded feed sizes](reviews/2026-09-17-accuracy-round7b-details.json), and
[acceptance evidence](reviews/2026-09-17-acceptance.md) for the original fixture
context. Sizes, upstream contents and update durations can change.
