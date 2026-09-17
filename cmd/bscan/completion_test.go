package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/config"
)

// Run the actual main path in an isolated process, including exit codes and
// stderr handling; no command help test can initialize the developer's keys.
func TestCLIPolishProcess(t *testing.T) {
	if os.Getenv("BSCAN_CLI_POLISH_PROCESS") != "1" {
		return
	}
	var args []string
	if err := json.Unmarshal([]byte(os.Getenv("BSCAN_CLI_POLISH_ARGS")), &args); err != nil {
		panic(err)
	}
	os.Args = append([]string{"bscan"}, args...)
	main()
	os.Exit(0)
}

func polishCLI(t *testing.T, home string, args ...string) (string, string, int) {
	t.Helper()
	data, _ := json.Marshal(args)
	cmd := exec.Command(os.Args[0], "-test.run=^TestCLIPolishProcess$")
	cmd.Env = append(os.Environ(), "BSCAN_CLI_POLISH_PROCESS=1", "BSCAN_CLI_POLISH_ARGS="+string(data),
		"BONGSU_HOME="+home, "BONGSU_CONFIG=", "BONGSU_NO_UPDATE_CHECK=1", "BONGSU_OFFLINE=1",
		"BSCAN_LLM_BASE_URL=", "BSCAN_LLM_MODEL=", "GORACE=atexit_sleep_ms=0")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	code := 0
	if err := cmd.Run(); err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			code = exit.ExitCode()
		} else {
			t.Fatal(err)
		}
	}
	return stdout.String(), stderr.String(), code
}

func TestBuildIdentity(t *testing.T) {
	oldVersion, oldCommit, oldDate := version, commit, buildDate
	t.Cleanup(func() { version, commit, buildDate = oldVersion, oldCommit, oldDate })
	version, commit, buildDate = "dev", "", ""
	info := &debug.BuildInfo{GoVersion: "go1.27.1", Main: debug.Module{Path: "example.test/module", Version: "v1.2.3"}, Settings: []debug.BuildSetting{
		{Key: "vcs.revision", Value: "abc123"}, {Key: "vcs.time", Value: "2026-09-17T00:00:00Z"}, {Key: "vcs.modified", Value: "true"},
	}}
	v, c, d, g, m := buildIdentity(info)
	if v != "v1.2.3" || c != "abc123 (modified)" || d != "2026-09-17T00:00:00Z" || g != "go1.27.1" || m != "example.test/module" {
		t.Fatalf("build info = %q %q %q %q %q", v, c, d, g, m)
	}
	version, commit, buildDate = "release", "explicit-commit", "explicit-date"
	v, c, d, _, _ = buildIdentity(info)
	if v != version || c != commit || d != buildDate {
		t.Fatalf("linker overrides lost: %q %q %q", v, c, d)
	}
	version, commit, buildDate = "dev", "", ""
	v, c, d, g, m = buildIdentity(nil)
	if v != "dev" || c != "unknown" || d != "unknown" || g != runtime.Version() || m != "github.com/ziozzang/bongsu-scanner" {
		t.Fatalf("fallback = %q %q %q %q %q", v, c, d, g, m)
	}
}

func TestVersionAboutAndGlobalErrors(t *testing.T) {
	home := t.TempDir()
	baseline, stderr, code := polishCLI(t, home, "version")
	if code != 0 || stderr != "" {
		t.Fatalf("version: exit=%d stderr=%s", code, stderr)
	}
	for _, field := range []string{"bscan ", "Commit:", "Build date:", "Go: go", "Platform: " + runtime.GOOS + "/" + runtime.GOARCH, "Module: github.com/ziozzang/bongsu-scanner"} {
		if !strings.Contains(baseline, field) {
			t.Errorf("version lacks %q: %s", field, baseline)
		}
	}
	for _, args := range [][]string{{"--version"}, {"-v"}, {"--quiet", "--no-color", "version"}, {"--log-format=json", "version"}} {
		stdout, stderr, code := polishCLI(t, home, args...)
		if stdout != baseline || stderr != "" || code != 0 {
			t.Errorf("%v: stdout=%s stderr=%s code=%d", args, stdout, stderr, code)
		}
	}
	stdout, _, code := polishCLI(t, home, "about")
	if code != 0 || !strings.HasPrefix(stdout, baseline) || !strings.Contains(stdout, "LICENSE") || !strings.Contains(stdout, "THIRD_PARTY_NOTICES.txt") {
		t.Fatalf("about: %s (exit %d)", stdout, code)
	}
	for _, args := range [][]string{{"--quiet", "unknown"}, {"--log-format", "invalid", "version"}, {"--config"}, {"--config=", "version"}, {"completion", "powershell"}} {
		_, stderr, code := polishCLI(t, home, args...)
		if code != 1 || !strings.Contains(stderr, "bscan:") {
			t.Errorf("%v: error must remain visible, code=%d stderr=%s", args, code, stderr)
		}
	}
}

func TestGlobalConfigPrecedenceAndRestore(t *testing.T) {
	t.Setenv("BONGSU_CONFIG", "environment.yaml")
	options, args, err := parseGlobalFlags([]string{"--config", "override.yaml", "--quiet", "--log-format=json", "scan", "--verbose", "target"})
	if err != nil || strings.Join(args, " ") != "scan --verbose target" || !options.quiet || options.logFormat != "json" {
		t.Fatalf("parse: %+v %v %v", options, args, err)
	}
	restore, err := applyGlobalFlags(options)
	if err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("BONGSU_CONFIG"); got != "override.yaml" {
		t.Errorf("override = %q", got)
	}
	restore()
	if got := os.Getenv("BONGSU_CONFIG"); got != "environment.yaml" {
		t.Errorf("restored environment = %q", got)
	}
	options, _, _ = parseGlobalFlags([]string{"version"})
	restore, err = applyGlobalFlags(options)
	if err != nil {
		t.Fatal(err)
	}
	defer restore()
	if got := os.Getenv("BONGSU_CONFIG"); got != "environment.yaml" {
		t.Errorf("environment fallback = %q", got)
	}
}

func TestQuietAndJSONScan(t *testing.T) {
	home, target := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "go.mod"), []byte("module example.test/fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"text", "quiet", "json"} {
		t.Run(mode, func(t *testing.T) {
			var args []string
			if mode == "quiet" {
				args = []string{"-q"}
			} else {
				args = []string{"--log-format", mode}
			}
			output := t.TempDir()
			args = append(args, "scan", "--no-sign", "--verbose", "--output", output, target)
			stdout, stderr, code := polishCLI(t, home, args...)
			if code != 0 || !strings.Contains(stdout, ".cdx.json") {
				t.Fatalf("scan exit=%d stdout=%s stderr=%s", code, stdout, stderr)
			}
			switch mode {
			case "quiet":
				if stderr != "" {
					t.Errorf("quiet stderr = %s", stderr)
				}
			case "text":
				if !strings.Contains(stderr, "[scan:start]") || !strings.Contains(stdout, "scan complete:") {
					t.Errorf("text compatibility: stdout=%s stderr=%s", stdout, stderr)
				}
			case "json":
				stages := map[string]bool{}
				for _, line := range strings.Split(strings.TrimSpace(stderr), "\n") {
					var event map[string]string
					if err := json.Unmarshal([]byte(line), &event); err != nil {
						t.Fatalf("invalid JSON event %q: %v", line, err)
					}
					if len(event) != 4 || event["level"] != "info" || event["msg"] == "" {
						t.Errorf("invalid event: %v", event)
					}
					if _, err := time.Parse(time.RFC3339Nano, event["ts"]); err != nil {
						t.Error(err)
					}
					stages[event["stage"]] = true
				}
				if !stages["scan:start"] || stages["scan:complete"] || !strings.Contains(stdout, "scan complete:") {
					t.Errorf("incorrect result/log separation: stages=%v stdout=%s", stages, stdout)
				}
			}
		})
	}
}

func TestConcurrentLogEvents(t *testing.T) {
	restore, err := applyGlobalFlags(globalFlags{logFormat: "json"})
	if err != nil {
		t.Fatal(err)
	}
	defer restore()
	output, err := captureBatchStderr(t, func() error {
		var wg sync.WaitGroup
		for i := range 20 {
			wg.Add(1)
			go func() { defer wg.Done(); logf("batch", "worker %d: newline\nquote=\"", i) }()
		}
		wg.Wait()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 20 {
		t.Fatalf("got %d event lines", len(lines))
	}
	for _, line := range lines {
		if !json.Valid([]byte(line)) {
			t.Errorf("interleaved JSON: %s", line)
		}
	}
}

func TestCompletionHelpSync(t *testing.T) {
	home := t.TempDir()
	flagLine := regexp.MustCompile(`(?m)^  -([A-Za-z][A-Za-z0-9-]*)(?:[ \t]|$)`)
	for _, command := range commandRegistry() {
		if command.Path == "" {
			continue // root flags are introspected directly
		}
		t.Run(command.Path, func(t *testing.T) {
			args := append(strings.Fields(command.Path), "--help")
			stdout, stderr, code := polishCLI(t, home, args...)
			if code != 0 {
				t.Fatalf("%v: exit %d: %s", args, code, stderr)
			}
			help := stdout + stderr
			actual := map[string]bool{}
			for _, match := range flagLine.FindAllStringSubmatch(help, -1) {
				actual[match[1]] = true
			}
			for _, f := range command.Flags {
				if f.Hidden {
					continue
				}
				if !actual[f.Name] || !strings.Contains(help, f.Description) {
					t.Errorf("registry flag --%s absent or description changed in actual help:\n%s", f.Name, help)
				}
				def := strings.ReplaceAll(f.Default, "$BONGSU_HOME", home)
				def = strings.ReplaceAll(strings.ReplaceAll(def, "$BSCAN_LLM_BASE_URL", ""), "$BSCAN_LLM_MODEL", "")
				if def != "" && def != "false" && def != "0" && def != "0s" {
					if !strings.Contains(help, "(default "+def+")") && !strings.Contains(help, fmt.Sprintf("(default %q)", def)) {
						t.Errorf("--%s default %q is out of sync", f.Name, def)
					}
				}
				delete(actual, f.Name)
			}
			if len(actual) != 0 {
				t.Errorf("actual flags missing from registry: %v", actual)
			}
		})
	}
	entries, err := os.ReadDir(home)
	if err != nil || len(entries) != 0 {
		t.Fatalf("help created config/key files: %v, %v", entries, err)
	}
}

func TestCompletionScripts(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish"} {
		t.Run(shell, func(t *testing.T) {
			var script bytes.Buffer
			if err := writeCompletion(&script, shell); err != nil {
				t.Fatal(err)
			}
			for _, command := range commandRegistry() {
				for _, word := range completionWords(commandRegistry(), command) {
					needle := word
					if shell == "fish" {
						needle = shellQuote(strings.TrimLeft(word, "-"))
					}
					if !strings.Contains(script.String(), needle) {
						t.Errorf("script lacks %q for %q", word, command.Path)
					}
				}
			}
			path := filepath.Join(t.TempDir(), "completion."+shell)
			if err := os.WriteFile(path, script.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := exec.LookPath(shell); err != nil {
				t.Logf("%s unavailable; content checked, syntax execution skipped", shell)
				return
			}
			if out, err := exec.Command(shell, "-n", path).CombinedOutput(); err != nil {
				t.Fatalf("syntax: %v: %s", err, out)
			}
		})
	}
}

func TestBashCompletionContexts(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash unavailable")
	}
	var script bytes.Buffer
	if err := writeCompletion(&script, "bash"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ words, want, absent string }{
		{"bscan ''", "scan", "--workers"},
		{"bscan --config 'path with spaces.yaml' --quiet scan --wo", "--workers", "--config"},
		{"bscan --log-format=json db up", "update", "scan"},
		{"bscan db update --nv", "--nvd-years", "--format"},
		{"bscan scramble de", "decrypt", "scan"},
		{"bscan completion ''", "fish", "scan"},
		{"bscan scan --output ''", "", "--workers"},
		{"bscan scan -- --wo", "", "--workers"},
		{"bscan scan target --wo", "", "--workers"},
	} {
		body := script.String() + "\nCOMP_WORDS=(" + tc.words + "); COMP_CWORD=$((${#COMP_WORDS[@]}-1)); _bscan; printf '%s\\n' \"${COMPREPLY[@]}\"\n"
		out, err := exec.Command("bash", "--noprofile", "--norc", "-c", body).CombinedOutput()
		if err != nil || (tc.want != "" && !strings.Contains(string(out), tc.want)) || strings.Contains(string(out), tc.absent) {
			t.Errorf("%s: got %q err=%v want=%q absent=%q", tc.words, out, err, tc.want, tc.absent)
		}
	}
}

func TestHelpRoutesWithoutConfig(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "scaner.yaml"), []byte("offline: invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"key", "show", "--help"}, {"help", "scan"}, {"db", "--help"}, {"completion", "--help"}, {"--quiet", "--help"}} {
		stdout, stderr, code := polishCLI(t, home, args...)
		if code != 0 || !strings.Contains(stdout+stderr, "Usage") {
			t.Errorf("%v: exit=%d stdout=%s stderr=%s", args, code, stdout, stderr)
		}
	}
	// run still treats native flag.ErrHelp as successful.
	if err := run(context.Background(), []string{"hash", "--help"}); err != nil {
		t.Fatal(err)
	}
}

var updateCommandReference = flag.Bool("update-command-reference", false, "regenerate docs/commands.md")

func TestCommandReference(t *testing.T) {
	path := filepath.Join("..", "..", "docs", "commands.md")
	want := commandReference()
	if *updateCommandReference {
		if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != want {
		t.Fatal("docs/commands.md is stale; run go generate ./cmd/bscan")
	}
}

func commandReference() string {
	var b strings.Builder
	b.WriteString(`# Command reference

<!-- Generated by go generate ./cmd/bscan. Do not edit directly. -->

Run ` + "`bscan [global flags] COMMAND [command flags] [arguments]`" + `.
Global flags must precede the command; command flags precede positional arguments.
Go-style single and double dashes are accepted. Boolean values use ` + "`--flag=false`" + `.
Use ` + "`--`" + ` to end flag parsing. Every command accepts ` + "`--help`" + ` / ` + "`-h`" + `.

## Output

Stdout contains only primary results: tables, JSON, rendered reports, verification
results, version/help text, scan complete result lines, and output paths. This
contract is identical in text, JSON-log, and quiet modes. DB status metadata is a
primary result; DB update/import/convert metadata and update installation status
are operational summaries on stderr. Successful update checks print current and
latest versions on stdout and return 0 whether or not an update is available
(there is no update-available exit code 4); failed checks still return 1.

Progress, warnings, and operational summaries use the shared stderr logger.
` + "`--quiet`" + ` / ` + "`-q`" + ` suppresses these logs; terminating errors remain visible
through the single top-level error printer. ` + "`--log-format=json`" + ` emits one JSON
object per log line with ` + "`ts` (UTC RFC3339), `level` (info/warn), `stage`, and `msg`" + `.
The log format never changes the result format or moves scan complete lines to
stderr. No color is emitted; ` + "`--no-color`" + ` is a compatibility flag.
Background update notices are disabled in quiet/JSON mode. Internal configuration
diagnostics are outside the command logger.

Version information uses linker values ` + "`main.version`, `main.commit`, `main.buildDate`" + `
when supplied, otherwise module and VCS build metadata where available. Missing
commit/date metadata is reported as unknown; modified source trees are marked.
` + "`--version`" + ` and ` + "`-v`" + ` are aliases for ` + "`version`" + `.

## Shell completion

` + "```sh\nbscan completion bash > ~/.bscan.bash\nsource ~/.bscan.bash\nbscan completion zsh > ~/.bscan.zsh\n# After compinit:\nsource ~/.bscan.zsh\nbscan completion fish > ~/.config/fish/completions/bscan.fish\n```" + `

Scripts enumerate commands and flags, understand nested commands and global
flag values, and fall back to shell filename completion for arguments.
Regenerate this reference with ` + "`go generate ./cmd/bscan`" + `; ordinary tests compare
it with the committed file and compare registry flags/defaults/descriptions with
actual command help. Hidden profiling flags are documented but not suggested.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success, help, version, completion generation, or a successful update --check (including an available update) |
| 1 | Invalid arguments or execution/verification failure |
| 2 | A finding reaches --fail-on in match, scan --match, or batch --match; takes precedence over accompanying errors except cancellation |
| 3 | The walk was partial (permission denied, I/O errors, limits) and --fail-on-partial was set; no SBOM is written |
| 130 | Interrupted (context canceled); deadlines remain execution errors |

Negative --workers and --jobs values are rejected with exit 1. Offline mode rejects
registry:// and oci:// targets before network access in scan, batch, and --match;
docker:// uses the local daemon and remains allowed.

## Environment variables

| Variable | Meaning / default |
| --- | --- |
| BONGSU_HOME | Private configuration, identity, database, and cache root; default ~/.bongsu |
| BONGSU_CONFIG | Configuration file override; --config PATH takes precedence; otherwise $BONGSU_HOME/scaner.yaml |
| BONGSU_NO_UPDATE_CHECK | Disable background release checks; unset/empty/0/false/no/off leaves them enabled |
| BONGSU_OFFLINE | Disable outbound registry/update/LLM requests; same truth rules; also enabled by offline: true |
| BONGSU_WALK_WORKERS | Positive directory-walk worker override (takes precedence over --workers); otherwise --workers or min(8, CPUs) |
| BSCAN_LLM_BASE_URL | Default --llm-base-url; empty until explicitly configured |
| BSCAN_LLM_MODEL | Default --llm-model; empty until explicitly configured |
| BSCAN_LLM_API_KEY | Default API-key environment variable; --llm-key-env can select another variable |
| GITHUB_TOKEN | Token for explicit release updates; never sent by background release checks |

## Configuration keys

Configuration override plumbing sets BONGSU_CONFIG before configuration consumers.
The current internal/config package does not yet honor this variable. Selecting
a different file is rejected with an explicit error until that package is migrated;
no requested configuration is silently ignored. This also applies to BONGSU_CONFIG
set directly in the environment.

The default filename is intentionally spelled ` + "`scaner.yaml`" + `.
Relative identity paths resolve under BONGSU_HOME; ~/ paths resolve under the
user home directory. Changing the configuration file does not change BONGSU_HOME.
Unknown and duplicate keys produce warnings; the last duplicate wins.

| Key | Default | Meaning |
| --- | --- | --- |
| signer | empty | Signing identity label |
| private_key | empty | Private key path; empty selects $BONGSU_HOME/signing.key |
| key_path | empty | Compatibility alias for private_key |
| public_key | empty | Public key path; default local signing.pub |
| hash | sha256 | Stored hash preference; artifact manifests use SHA-256 |
| formats | [spdx, cyclonedx] | Stored format preference; scan --format controls output |
| concurrency | 2 | Default batch concurrency; values below 1 normalize to 1 |
| trusted_keys | empty map | Flat name-to-public-key map; release pins release checksum signatures |
| offline | false | Disable network operations, including loopback LLM requests |
| db_require_signature | false | Require trusted database signatures for CLI consumers |
| update_require_signature | false | Require trusted release checksum signatures |
| signature_min_version | 1 | Oldest accepted signature format: 1 or 2 |

### Command defaults

The scan, match, and db blocks supply command flag defaults. Explicit CLI flags
(including false, zero and empty strings) override file values; omitted file keys
retain built-in defaults. Repeated --exclude flags replace scan.excludes.
Lists accept flow sequences or indented dash items. Invalid booleans and integers
are errors; unknown nested keys warn. Duplicate blocks replace earlier blocks.

Run bscan config show to print the merged configuration as YAML without creating
files. Run bscan config init to create a commented default template without
signing keys; it refuses to overwrite an existing file. bscan init still initializes
the signing identity. Neither command prints private key contents.

| Block | Keys | Applies to |
| --- | --- | --- |
| scan | excludes, one_file_system, workers, redact_ip, no_host_metadata, skip_binaries, include_declared, containers, fail_on_partial, output, format | scan and batch |
| match | severity_source, exclude_unimportant, min_severity, fail_on, only_fixed, db_isolation | match and scan/batch --match |
| match | report_formats | --report for scan/batch --match only; never enables matching |
| db | sources, ecosystems, alpine_releases, nvd_years, max_feed_bytes, max_feed_uncompressed, keep_raw, mirror | db update; keep_raw also applies to db convert |

Keys use underscores, while their corresponding CLI flags use hyphens. Exceptions:
scan.excludes maps to --exclude; db.sources to --source; db.ecosystems to
--ecosystem; db.alpine_releases to --alpine-release; db.keep_raw is the inverse of
--no-keep-raw. Defaults match the flag tables below (keep_raw is true; lists are
empty and defer to existing updater defaults). Relative scan.output paths resolve
from the working directory. Top-level formats remains a stored preference;
scan.format supplies the command default.

## Commands and flags

An empty default is shown as ` + "`\"\"`" + `; environment-dependent defaults use variable
names rather than the generating machine's paths or credentials.

`)
	for _, command := range commandRegistry() {
		name := "bscan"
		if command.Path != "" {
			name += " " + command.Path
		}
		fmt.Fprintf(&b, "### %s\n\n%s.\n\n```text\n%s\n```\n\n", name, command.Description, strings.TrimSpace(name+" "+command.Arguments))
		if len(command.Flags) == 0 {
			b.WriteString("No command-specific flags.\n\n")
			continue
		}
		b.WriteString("| Flag | Default | Description |\n| --- | --- | --- |\n")
		for _, f := range command.Flags {
			def := f.Default
			if def == "" {
				def = `""`
			}
			description := f.Description
			if f.Hidden && !strings.Contains(description, "(hidden)") {
				description += " (hidden)"
			}
			fmt.Fprintf(&b, "| `%s` | `%s` | %s |\n", flagSpelling(f.Name), strings.ReplaceAll(def, "|", "\\|"), strings.ReplaceAll(description, "|", "\\|"))
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func TestConfigOverrideNeverSilentlyIgnored(t *testing.T) {
	home := t.TempDir()
	t.Setenv("BONGSU_HOME", home)
	custom := filepath.Join(t.TempDir(), "custom.yaml")
	t.Setenv("BONGSU_CONFIG", custom)
	if err := os.WriteFile(custom, []byte("offline: invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Once the config package adds path support, the selected file must be read.
	// Until then the CLI must reject it before a command can create any files.
	path, err := config.Path()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(path) == custom {
		if err := validateConfigOverride(); err != nil {
			t.Fatal(err)
		}
		if _, _, err := config.Load(); err == nil {
			t.Fatal("custom malformed configuration was ignored")
		}
	} else {
		if err := run(context.Background(), []string{"init"}); err == nil || !strings.Contains(err.Error(), "configuration override unavailable") {
			t.Fatalf("unimplemented override must fail closed: %v", err)
		}
		entries, err := os.ReadDir(home)
		if err != nil || len(entries) != 0 {
			t.Fatalf("override failure wrote to the default home: %v, %v", entries, err)
		}
	}
	t.Setenv("BONGSU_CONFIG", filepath.Join(home, "scaner.yaml"))
	if err := validateConfigOverride(); err != nil {
		t.Fatalf("selecting default path must remain valid: %v", err)
	}
}

func TestCompletionRegistryCoversDispatch(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	registered := map[string]bool{}
	for _, command := range commandRegistry() {
		if command.Path != "" && !strings.Contains(command.Path, " ") {
			registered[command.Path] = true
		}
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "run" {
			continue
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			clause, ok := node.(*ast.CaseClause)
			if !ok {
				return true
			}
			for _, expr := range clause.List {
				literal, ok := expr.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					continue
				}
				name, _ := strconv.Unquote(literal.Value)
				if strings.HasPrefix(name, "-") {
					continue
				}
				if !registered[name] {
					t.Errorf("dispatched command %q missing from registry", name)
				}
				delete(registered, name)
			}
			return true
		})
	}
	if len(registered) != 0 {
		t.Errorf("registry commands missing from dispatch: %v", registered)
	}
}

func TestHiddenProfilingFlagsStillAccepted(t *testing.T) {
	for _, command := range []string{"scan", "match"} {
		_, stderr, code := polishCLI(t, t.TempDir(), command, "--cpuprofile", "unused.cpu", "--memprofile", "unused.mem", "--help")
		if code != 0 || strings.Contains(stderr, "not defined") {
			t.Errorf("%s hidden flags: exit=%d stderr=%s", command, code, stderr)
		}
	}
}

func TestCommandReferenceNoTrailingWhitespace(t *testing.T) {
	for n, line := range strings.Split(commandReference(), "\n") {
		if line != strings.TrimRight(line, " \t") {
			t.Errorf("line %d has trailing whitespace", n+1)
		}
	}
}
