# Configuration

Configuration and keys are stored at `~/.bongsu/scaner.yaml`,
`~/.bongsu/signing.key` (mode 0600), and `~/.bongsu/signing.pub`.
`BONGSU_HOME` can override the state directory. The configuration file is selected
in this order: global `--config PATH`, `BONGSU_CONFIG`, then
`$BONGSU_HOME/scaner.yaml`. Place `--config` before the command:

```sh
BONGSU_HOME=/var/lib/bscan bscan --config /etc/bscan/scaner.yaml config show
```

Selecting another configuration file does not relocate keys, the database or
caches. Default keys and database stay under `BONGSU_HOME`; relative identity
paths also resolve there, while `~/` paths resolve under the user's home.
Explicit `private_key` / `public_key` settings and `--db DIR` can select other
locations. The spelling `scaner.yaml` is intentional.

`scaner.yaml` must use UTF-8; an optional leading UTF-8 BOM is accepted, as
are LF and CRLF line endings. UTF-16, invalid UTF-8, and non-printable characters
in keys are rejected. Double-quoted scalars use Go `strconv.Unquote` escapes;
single-quoted scalars keep backslashes literal and represent a quote with `''`.
Quote keys and values containing `:`, `#`, or quotes when needed.
`trusted_keys` must be an indented, flat block map; inline maps and flow sequences
are rejected there and for scalar settings. The existing `formats: [spdx,
cyclonedx]` list is supported. Unknown keys are ignored with warnings available
to CLI consumers; duplicate keys use the last value and produce a warning.
Malformed security settings cause a configuration error, never a fallback to
defaults.

Command defaults can be stored in the `scan`, `match`, and `db` blocks below.
Precedence is **explicit CLI flag > configuration file > built-in default**.
Explicit `--flag=false`, `--workers=0`, and empty string values override the
file as well. Repeated `--exclude` flags replace the configured excludes; lists
are not appended. Lists accept `[a, b]` or indented `- value` items. Invalid
boolean/integer values are errors; unknown keys inside these blocks warn.

```sh
bscan config init  # create a commented template; refuse to overwrite a file
bscan config show  # print file values merged with built-in defaults as YAML
```

`config init` creates no signing keys. The existing `bscan init` continues to
initialize the signing identity. `config show` identifies the selected file in a YAML comment and does not create
files or print
key contents (identity settings contain paths, not private key material).

```yaml
scan:
  excludes: []             # e.g. ["/var/cache", "node_modules"]
  one_file_system: false
  workers: 0               # automatic worker count
  redact_ip: false
  no_host_metadata: false
  skip_binaries: false
  include_declared: false
  containers: false
  fail_on_partial: false
  output: "."
  format: both
match:
  severity_source: distro
  exclude_unimportant: false
  min_severity: ""
  fail_on: ""
  only_fixed: false
  db_isolation: auto
  report_formats: []       # e.g. [html, sarif]; scan/batch --match only
db:
  sources: []              # empty reuses installed choices, or built-in defaults
  ecosystems: []           # empty reuses installed choices, or built-in defaults
  alpine_releases: []      # empty reuses installed choices, or built-in defaults
  nvd_years: ""            # saved years, or current year and previous two
  # max_feed_bytes: 1073741824  (built-in default; uncomment to override)
  # max_feed_uncompressed: 34359738368  (built-in default; uncomment to override)
  keep_raw: true           # inverse of --no-keep-raw
  mirror: ""
```

Scan settings also apply to `batch`. Match settings apply to `match` and
`scan/batch --match`; `report_formats` supplies `--report` only when matching is
explicitly enabled. DB settings apply to `db update`, with `keep_raw` also
applying to `db convert`. Relative scan output paths are relative to the working
directory, just like `--output`. Existing top-level `formats` remains a stored
preference; use `scan.format` to set the scan command's format default.

Security settings (defaults shown):

```yaml
offline: false
db_require_signature: false
update_require_signature: false
signature_min_version: 1
trusted_keys:
  # release: "path/to/publisher.pub"
```

`offline` or `BONGSU_OFFLINE=1` disables database/release updates, background
release checks, LLM requests, and remote `registry://` / `oci://` scans.
Scan and batch (including `--match`) reject remote registry targets before
network access. Local directories, archives, and `docker://` images from the
local daemon remain available.
`db_require_signature` exposes the trusted
signature policy for database refresh consumers; `update_require_signature` requires a trusted
release signature even without the update command's `--require-signature` flag.
`signature_min_version` accepts `1` (compatibility default) or `2`; setting it to
`2` rejects v1 records in `verify`/signature `check` and release verification. This minimum does
not itself require a signature: pin a `release` key or enable
`update_require_signature` to require authenticated updates.

## Logging

Place global logging flags before the command: `bscan --quiet scan .` suppresses
progress logs; `bscan --log-format=json scan .` emits structured progress
and operational summaries on stderr. Primary results, including `scan complete`
lines and output paths, remain on stdout. Errors remain visible, and so do
warnings that change how results must be read (catalog coverage gaps, failed
feed downloads, unavailable LLM review): a quiet run that matched nothing
because the catalog lacks the host's distribution still says so. These flags
also apply to database, matching, and update command logs.

## Memory target

The global `--memory-limit SIZE` (for example `512MiB` or `1GiB`) overrides
`BSCAN_MEMORY_LIMIT`. This is a soft Go heap target, not a hard RSS or container
limit; the garbage collector works harder near it rather than aborting.
