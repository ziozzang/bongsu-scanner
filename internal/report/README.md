# Report schema version 1

`Render(w, format, Input)` supports `html`, `markdown` (`md`), `json`, `csv`,
and `sarif`. `LoadMatchJSON` accepts a single object emitted by
`match.Write(w, "json", report, document)`, tolerates unknown fields, and rejects
multiple values and arrays. It does not accept this package's versioned envelope.

JSON has `report_schema_version: 1`, `generated_by: {name, version}`,
`generated_at` (UTC RFC 3339), `target`, `sbom_file`, `database` (the matcher DB
metadata), `options` (match.Options), `options_note`, `summary`, `scan`, optional
`os`, `image`, `host`, `packages`, `top_packages`, and `findings`. Summary contains
`subjects`, `matched_packages`, `findings`, six `by_severity` counts, and `skipped`.
Missing scan metadata is null, not an assertion of completeness.

Findings contain package, version, ecosystem (with optional `:release`), purl,
id, related_ids, severity, numeric score, vector, fixed_in, matched_by,
confidence, summary (at most 200 Unicode characters), links, assessment_status,
assessment_reason, source, and optional withdrawn. They use the matcher's order:
severity descending, package name, ID, subject reference. Display strings remove
terminal controls. Assessment remains advisory and does not suppress findings.
The original match.Report JSON representation is unchanged.

Package rollups are keyed by package name plus ecosystem/release and include
by_severity, worst_fix_version, findings_without_fix, and optional fix_note.
Worst fix means the highest comparable reported version using the ecosystem's
version ordering. Different affected branches may not have one universal fix;
this value is not an upgrade recommendation or a guarantee of resolution.
Incomparable versions are called out, not compared lexically. Top packages are
ranked by critical + high count, then critical count, then name/ecosystem.

`--from` cannot reconstruct matching options: match JSON does not contain them.
The options block is caller-supplied; its zero values in the CLI are not evidence
of the original policy. `--sbom` supplies context from bscan CycloneDX root
properties/OS components or SPDX root annotations/comments/OS packages.
`--title` overrides the displayed target. Without a SBOM, target defaults to the
input filename. Output files are replaced atomically only after rendering succeeds.

CSV uses RFC 4180 CRLF records with one finding per row. The final column on the
first finding contains all report metadata, including package rollups, as JSON;
subsequent rows leave it empty. Empty reports have a header only, with the metadata JSON in the final header cell.
SARIF 2.1.0 contains one run, vulnerability-ID rules and logical package locations;
its run properties contain report metadata and result properties contain the
finding fields. Rule security-severity uses the highest available score per ID,
with severity-band lower bounds when a numeric score is unavailable.

Markdown caps finding and package tables at 1,000 rows and links to `report.json`;
create the companion file with `--format json -o report.json` in the same directory.
HTML contains inline styles and script only, renders 200 findings at a time,
and filters/sorts the full dataset. Over 10,000 findings the embedded rows use
gzip/base64 and the browser's native DecompressionStream (modern browsers).
Missing purls receive a generic package URL with an ecosystem qualifier.
JavaScript-disabled/older browsers retain the first 200 findings and context
(and the first 50 package groups for compressed reports),
with an explicit notice to export JSON/CSV for all rows. Compression reduces
repeated data but there is no fixed byte limit for arbitrarily large unique text.
