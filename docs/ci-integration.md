# CI integration

Build bscan from source with Go 1.25 or newer (this checkout selects toolchain
Go 1.27.1). The examples below run in a bscan source checkout; for an application
repository, build in a separate pinned bscan checkout and put the resulting
binary on the application's PATH before the scan step. No release tag is
assumed while the format is still Unreleased.

Supply a trusted `catalog.tar.gz` as a job input, exported from an existing
catalog using the command below. For a connected deployment, refresh that
catalog in a separate scheduled database-update job. Importing the export
lets these scan jobs use `BONGSU_OFFLINE=1` without downloading vulnerability
feeds. The examples cache only the catalog, never signing keys or configuration.

```sh
bscan -q db export catalog.tar.gz
```

The imported catalog must cover the application's ecosystems/releases. Check
`missing_coverage`, `skipped` and `db.updated_at` in the
[findings document](findings-json.md); a successful process exit alone does not
establish coverage. The tiny Alpine-only validation catalog is a test input,
not a catalog suitable for every application.

## Flag placement and exit status

The working scan command is:

```sh
bscan --findings-exit-code 3 scan --match --report sarif --fail-on HIGH --output out .
```

`--findings-exit-code`, `--memory-limit`, `-q` and `--log-format` are **global**
flags and precede `scan`. All listed flags are in the
[generated command reference](commands.md). Placing `--findings-exit-code`
after `scan`, as if it were a scan flag, fails with exit 1.

| Exit | Meaning / CI treatment |
| --- | --- |
| `0` | Command succeeded; no configured findings threshold was reached. Findings below the threshold, including UNKNOWN, can still exist. |
| `1` | Invalid arguments or operational/verification failure. Fail the job. |
| `2` (default) or custom | A retained finding meets `--fail-on`. Reports are written before this status. Go fatal errors also use 2, so a distinct custom code helps. |
| `3` | Partial walk when `--fail-on-partial` is enabled; no SBOM is written. With the example's custom findings code, 3 instead denotes the findings gate. |
| `130` | Interrupted/canceled. Do not swallow this as a findings result. |

These examples do not enable `--fail-on-partial`. If you add it, choose a
findings code other than 3 (for example 5) and update the CI exit handling.
Cancellation takes precedence over findings; findings take precedence over
accompanying errors. Always retain stderr and artifacts when investigating a
nonzero exit.

`--memory-limit 512MiB` is a soft Go heap target, not an RSS/container limit.
`--log-format json` writes progress to stderr as JSON lines; result files keep
their own formats. `-q` suppresses progress but keeps final errors visible.
`BONGSU_NO_UPDATE_CHECK=1` disables background release checks.
`BONGSU_OFFLINE=1` blocks outbound registry, update and LLM requests; scan a local
directory or local image source in these jobs. Building source and installing
CI actions still require cached dependencies or network access.

## GitHub Actions

Make `catalog.tar.gz` available at the checkout root before import (for example
as a trusted artifact from your database refresh job). The cache key includes
UTC date and archive hash, so a changed export or a new day cannot reuse an old
catalog. A cache hit skips import. The date and import shell commands were
validated locally; the hosted cache/upload services require a real CI run.

```yaml
name: bscan
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    env:
      BONGSU_HOME: ${{ runner.temp }}/bongsu
      BSCAN_BIN: ${{ runner.temp }}/bscan-bin
      BONGSU_OFFLINE: "1"
      BONGSU_NO_UPDATE_CHECK: "1"
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.27.1"
      # Provision catalog.tar.gz here from your trusted artifact producer.
      - name: Build from the checked-out source
        run: |
          go build -o "$BSCAN_BIN/bscan" ./cmd/bscan
          echo "$BSCAN_BIN" >> "$GITHUB_PATH"
      - id: day
        run: echo "date=$(date -u +%F)" >> "$GITHUB_OUTPUT"
      - id: catalog
        uses: actions/cache@v4
        with:
          path: ${{ env.BONGSU_HOME }}/db
          key: bscan-db-${{ runner.os }}-${{ steps.day.outputs.date }}-${{ hashFiles('catalog.tar.gz') }}
      - if: steps.catalog.outputs.cache-hit != 'true'
        run: bscan db import catalog.tar.gz
      - name: Scan and record findings gate
        id: scan
        shell: bash
        run: |
          status=0
          bscan --memory-limit 512MiB --log-format json --findings-exit-code 3 scan --match --report sarif --fail-on HIGH --output out . || status=$?
          echo "status=$status" >> "$GITHUB_OUTPUT"
          case "$status" in
            0) ;;
            3) echo "::warning::bscan findings meet HIGH; see SARIF and findings artifacts" ;;
            *) exit "$status" ;;
          esac
      - name: Upload to code scanning
        if: always() && steps.scan.outputs.status != '' && (steps.scan.outputs.status == '0' || steps.scan.outputs.status == '3')
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: out
          category: bscan
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: bscan-results
          path: out/
```

This keeps findings visible while keeping the job green for code 3 only. To
make findings block merging, add a final step with
`if: steps.scan.outputs.status == '3'` and `run: exit 3`, **after** the uploads.
Execution errors still fail. GitHub code scanning must be enabled and the token
must be allowed to upload security events. See GitHub's
[SARIF upload documentation](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file).

## GitLab CI

GitLab's `dependency_scanning` and `sast` report artifacts require GitLab security
report JSON; pointing either key at raw SARIF or findings JSON does not convert
it. This example converts findings to dependency-scanning schema 15.2.0 with
Python's standard library, and keeps the original SARIF as a downloadable
artifact. It preserves the advisory/package identity, maps NEGLIGIBLE to Info,
and uses the inventory source file as location (falling back to the findings
artifact when no source is available). It does not invent source-code line numbers.
See the [GitLab scanner integration contract](https://docs.gitlab.com/development/integrations/secure/)
and [dependency-scanning schema](https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/blob/v15.2.0/dist/dependency-scanning-report-format.json).

Use a runner image with Go 1.27.1 and Python 3 available. Provide the trusted
catalog export at the checkout root. `allow_failure:exit_codes` keeps code 3
visible as an allowed failure; operational errors still fail the pipeline.
Remove that block for a blocking findings gate. GitLab security UI features
depend on your instance's tier/configuration; ordinary artifacts remain available.

```yaml
bscan:
  stage: test
  # Runner image must contain Go 1.27.1 and Python 3.
  variables:
    BONGSU_HOME: "$CI_PROJECT_DIR/.bongsu"
    BSCAN_BIN: "$CI_PROJECT_DIR/.bscan-bin"
    BONGSU_OFFLINE: "1"
    BONGSU_NO_UPDATE_CHECK: "1"
  cache:
    key:
      files: [catalog.tar.gz]
    paths: [.bongsu/db/]
  script:
    - go build -o "$BSCAN_BIN/bscan" ./cmd/bscan
    - export PATH="$BSCAN_BIN:$PATH"
    - bscan db import catalog.tar.gz
    - |
      status=0
      bscan --memory-limit 512MiB --log-format json --findings-exit-code 3 scan --match --report sarif --fail-on HIGH --output out --exclude .bongsu --exclude .bscan-bin . || status=$?
      case "$status" in 0|3) ;; *) exit "$status" ;; esac
      python3 - <<'PY'
      import datetime, glob, hashlib, json
      paths = sorted(glob.glob("out/*.findings.json"))
      if not paths:
          raise SystemExit("No bscan findings documents produced")
      findings, times, tool = [], [], None
      for path in paths:
          with open(path) as stream:
              doc = json.load(stream)
          if doc.get("schema") != "bscan-findings/1":
              raise SystemExit("Unsupported bscan findings schema")
          times.append(datetime.datetime.fromisoformat(doc["generated_at"].replace("Z", "+00:00")))
          tool = doc["tool"]
          for item in doc["findings"]:
              subject = item["subject"]
              source = subject.get("properties", {}).get("bscan:source") or path
              identity = [path, subject["ref"], item["id"]]
              identifiers = list(dict.fromkeys([item["id"]] + item.get("related_ids", [])))
              severity = item["severity"].title()
              if severity == "Negligible":
                  severity = "Info"
              finding = {
                  "id": hashlib.sha256(json.dumps(identity).encode()).hexdigest(),
                  "name": item["id"],
                  "description": item["record"].get("summary") or item["id"],
                  "severity": severity,
                  "identifiers": [{"type": "cve" if value.startswith("CVE-") else "bscan",
                                   "name": value, "value": value} for value in identifiers],
                  "location": {"file": source, "dependency": {
                      "package": {"name": subject["name"]},
                      "version": subject.get("version", "")}},
              }
              if item.get("fixed_in"):
                  finding["solution"] = "Reported fixed versions: " + ", ".join(item["fixed_in"])
              findings.append(finding)
      scanner = {"id": "bscan", "name": "bscan", "version": tool["version"],
                 "vendor": {"name": "bongsu-scanner"}}
      report = {"version": "15.2.0", "vulnerabilities": findings, "scan": {
          "analyzer": scanner, "scanner": scanner, "type": "dependency_scanning",
          "start_time": min(times).strftime("%Y-%m-%dT%H:%M:%S"),
          "end_time": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"),
          "status": "success"}}
      with open("out/gl-dependency-scanning-report.json", "w") as stream:
          json.dump(report, stream)
      PY
      exit "$status"
  allow_failure:
    exit_codes: [3]
  artifacts:
    when: always
    paths: [out/]
    reports:
      dependency_scanning: out/gl-dependency-scanning-report.json
```

GitLab also offers native SARIF ingestion on supported Ultimate versions, but
its importer requires physical file locations. bscan SARIF currently records
logical package locations, so the native dependency-scanning conversion above
is the applicable route for these findings. See
[GitLab SARIF ingestion requirements](https://docs.gitlab.com/user/application_security/detect/sarif/).
Do not relabel dependency findings as SAST merely to satisfy an artifact key.

## Local validation

The build, export, import, date/cache-key shell step, PATH setup, scan commands,
exit-handling blocks and Python conversion above were executed locally against
the small Alpine v3.20 catalog and directory fixtures. Both JSON log and quiet
modes were exercised. The converted report was validated against GitLab's
15.2.0 JSON schema. HIGH gating returned 0 for the fixture's UNKNOWN findings;
a separate UNKNOWN-threshold run exercised custom findings exit 3. No hosted
GitHub/GitLab workflow or upload was run locally. A connected database refresh
is deliberately outside this offline validation path.
