# Round 5 — product hardening — 2026-09-17

Sequence of independent automated reviews and fix jobs after the round-4
work, each fix landing with regression tests and full verification.

| Step | Scope | Outcome |
|---|---|---|
| Fuzzing (45 targets) | every parser, feed converter, purl/version, config, signatures, tar/zip, SBOM loaders | 13 reliability defects fixed; seeds kept; `make fuzz-smoke` |
| CLI polish | version/about metadata, quiet and JSON logs, completion, generated command reference, exit codes 0/1/2/3/130 | done |
| Packaging | Dockerfile (16.8 MB), systemd/cron units, dist tarballs, multi-arch image workflow, darwin/windows/freebsd builds | done |
| Accuracy vs Trivy (before) | 6 images | inventory 99.75 %, CVE 94.9 %, 10 ranked gaps |
| Gap fixes | Ubuntu feed cap, declared-dependency provenance, Debian not-affected/undetermined, distro severity, rubysec source, OSGi versions, Yarn bundles | G1–G7 closed |
| Accuracy vs Trivy (after) | same digests | inventory 805/805, CVE 977/977 with unimportant included |
| Third-round review | matcher, declared deps, rubysec, feeds | 5 high + 6 medium found and fixed (urgency scoping, project-scoped precedence, bundler-audit range semantics, numeric CVSS, YAML gaps, 304 cap re-validation, same-tick catalog change detection) |
| Policy | severity defaults | vendor rating first with CVSS fallback; unimportant shown as NEGLIGIBLE; `--exclude-unimportant` |
| Features | binary runtime classification with CPEs, opt-in NVD CPE matching, registry:// pulls, config-file defaults | done; then hardened after a security review (registry credentials/redirects/error text/budgets, classifier markers, CPE normalization, config show masking) |
| Memory | cataloger regression 703 MB → 231 MB peak RSS on the host scan | fixed |

Current baselines on the same host: host scan ~14 s / ~240 MB, match ~5 s /
~290 MB, catalog build ~50 s (cached feeds). Full `go test -race` ~50 s.
