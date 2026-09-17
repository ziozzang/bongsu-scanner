# bscan documentation

Start with the [project README](../README.md) for installation, initialization
and a first scan. These guides separate user workflows from reference material.

| Task | Document |
| --- | --- |
| Set paths, defaults, logging, memory and offline policy | [Configuration](configuration.md) |
| Install archives; deploy containers, systemd or cron; update or run offline | [Deployment](../deploy/README.md) |
| Scan hosts, directories, images, registries or batches; understand inventory ownership | [Scanning and inventory](scanning.md) |
| Sign outputs, pin keys, verify artifacts or use the scrambler | [Signing and verification](signing.md) |
| Select/update feeds, inspect storage, convert/export/import a catalog | [Vulnerability database](vulnerability-database.md) |
| Understand RubySec conversion and Red Hat VEX archives/deltas | [Advisory sources](advisory-sources.md) |
| Match SBOMs, filter findings and generate reports | [Matching and reports](matching.md) |
| Understand supported ecosystems and release mapping | [Support matrix](support-matrix.md) |
| Interpret vendor ratings and CVSS policy | [Severity policy](severity-policy.md) |
| Consume the findings JSON schema and skip reasons | [Findings JSON](findings-json.md) |
| Gate CI on findings and upload reports | [CI integration](ci-integration.md) |
| Add optional environmental applicability annotations | [LLM review](llm-review.md) |
| Prepare and verify a release | [Releasing](releasing.md) |
| Read the proposed server submission design | [Roadmap](roadmap.md) |
| Look up every command and flag | [Generated command reference](commands.md) |
| Review release changes | [Changelog](../CHANGELOG.md) |

Historical [acceptance evidence](reviews/2026-09-17-acceptance.md) and
[distribution measurements](reviews/2026-09-17-accuracy-round7.md) describe their
recorded dates and commits; they are not the current support contract.

The [documentation audit](documentation-audit.md) records the v0.6.0 restructuring,
verified corrections and remaining verification limits (Korean).
