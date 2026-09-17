# Severity policy

`match` and `scan --match` default to `--severity-source distro`: use the
matched distribution's rating, falling back to CVSS when no ranked vendor
rating is available. `--severity-source cvss` retains CVSS selection, and
`--severity-source max` selects the higher vendor or CVSS rating. The numerical
CVSS score and vector remain available independently of the selected severity.

For Ubuntu affected entries, `ecosystem_specific.ubuntu_priority` takes
precedence over `ecosystem_specific.priority`, then a record-level severity
entry with `type: Ubuntu`, then generic urgency metadata. The original priority
is shown in the distro severity field in lowercase. Ubuntu `negligible` and
Debian `unimportant` are displayed as `NEGLIGIBLE`, included by default, and
counted under `Skipped["unimportant"]` when excluded with
`--exclude-unimportant`. A negligible or unimportant marker without a matching
range cannot lower a positive finding's severity. `priority_reason`, when
present, is retained in the JSON finding's affected ecosystem metadata.

Ubuntu `UBUNTU-CVE-YYYY-NNNN` identifiers are associated with their embedded
CVE for grouping and CVSS enrichment. Other CVEs listed only in `related` are
separate vulnerabilities and are not promoted to aliases. Updating the catalog
is necessary to apply this alias derivation to previously ingested exports.

For `RLSA-`, `ALSA-`, `RHSA-`, `USN-`, `DSA-`, and `DLA-` advisories without an
explicit vendor rating, a summary starting with `Critical:`, `Important:`,
`Moderate:`, or `Low:` (case-insensitive) supplies the distro rating; Important
maps to HIGH and Moderate to MEDIUM. CVSS policy, scores, and vectors are
unchanged. AlmaLinux `ALSA-`, `ALBA-`, and `ALEA-` records without a CVE alias
promote related CVEs to aliases for grouping and CVSS enrichment, preserving
`related`. This derivation runs on every catalog update, including conversion
cache hits; other sources' related IDs are not promoted by this rule.
