# Severity policy

`match` and `scan --match` default to `--severity-source distro`: use the
matched distribution's rating, falling back to CVSS when no ranked vendor
rating is available. `--severity-source cvss` retains CVSS selection, and
`--severity-source max` selects the higher vendor or CVSS rating. The numerical
CVSS score and vector remain available independently of the selected severity.

For Ubuntu affected entries, ranked `type: Ubuntu` scores in the release-local
`database_specific.cves_map.cves[].severity` take precedence. A single-CVE list
uses that CVE's rating; a multi-CVE advisory remains one finding and uses the
highest ranked Ubuntu rating in that list. This affected-entry rating also
outranks record-wide fallback ratings when equivalent findings merge. Mapped
ratings of equal scope (package, release and CVE set) merge by maximum severity;
`--exclude-unimportant` excludes that scope only when all its mapped ratings
are negligible or unimportant. Without
a usable mapped rating, `ecosystem_specific.ubuntu_priority` takes
precedence over `ecosystem_specific.priority`, then a record-level severity
entry with `type: Ubuntu`, then generic urgency metadata. The original priority
is shown in the distro severity field in lowercase. Ubuntu `negligible` and
Debian `unimportant` are displayed as `NEGLIGIBLE`, included by default, and
counted under `skipped["unimportant"]` when excluded with
`--exclude-unimportant`. A negligible or unimportant marker without a matching
range cannot lower a positive finding's severity. `priority_reason`, when
present, is retained in the JSON finding's affected ecosystem metadata.

Ubuntu `UBUNTU-CVE-YYYY-NNNN` identifiers are associated with their embedded
CVE for grouping and CVSS enrichment. Other CVEs listed only in `related` are
separate vulnerabilities and are not promoted to aliases. Updating the catalog
is necessary to apply this alias derivation to previously ingested exports.
When an affected entry supplies `cves_map`, its CVE list replaces the global
aliases for that hit and for grouping in that release. Different CVE sets on
source and binary affected entries retain independent identities, even within
the same USN. CVEs present only in another entry or release cannot join its
finding, trigger `--ignore`, or supply a suppressing status.

For `RLSA-`, `ALSA-`, `RHSA-`, `USN-`, `DSA-`, and `DLA-` advisories without an
explicit vendor rating, a summary starting with `Critical:`, `Important:`,
`Moderate:`, or `Low:` (case-insensitive) supplies the distro rating; Important
maps to HIGH and Moderate to MEDIUM. CVSS policy, scores, and vectors are
unchanged. AlmaLinux `ALSA-`, `ALBA-`, and `ALEA-` records without a CVE alias
promote related CVEs to aliases for grouping and CVSS enrichment, preserving
`related`. This derivation runs on every catalog update, including conversion
cache hits; other sources' related IDs are not promoted by this rule.

For Red Hat affected ecosystems, `database_specific.severity` on the affected
entry takes precedence over the record rating, regardless of the advisory ID.
The opt-in `redhat-vex` source supplies per-product impact and aggregate Red Hat
ratings; Critical/Important/Moderate/Low map to CRITICAL/HIGH/MEDIUM/LOW. CVSS
vectors remain independent and prefer a RHEL-scoped score from the VEX document.

Red Hat `redhat_status: not-affected` markers suppress positive matches for the
same package, advisory and release, like Debian markers. Unfixed findings carry
`distro_status` and no fixed version. `under-investigation`, `fix-deferred`,
`will-not-fix`, and `out-of-support-scope` use low confidence; `affected` retains
normal range confidence. These statuses describe vendor disposition, not a
change to the CVSS score or proof of exploitability. Structured product status
is used; exclusions in free-text statements are not interpreted as version ranges.
For both `redhat_status` and `debian_status`, a not-affected marker with explicit
`versions` suppresses only equal versions (using ecosystem normalization), even
when the entry also has ranges. A binary NEVRA marker therefore cannot suppress
older versions covered by a source package's fixed range. Markers without
versions keep their existing behavior. The conversion-cache version is 6.
For stale conversion caches, a plain `bscan db update` re-parses retained raw
feeds (or re-downloads them when needed), restoring EVRs discarded by earlier
conversion; `--force` is not required. `bscan db convert` only converts the
existing catalog format: it neither re-fetches nor re-parses source feeds and
cannot restore discarded data.
