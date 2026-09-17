package main

//go:generate go test -run ^TestCommandReference$ -update-command-reference

import (
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

type commandFlag struct {
	Name, Default, Description, Kind string
	Hidden                           bool
}

type commandSpec struct {
	Path, Arguments, Description string
	Flags                        []commandFlag
}

func flagsFromSet(fs *flag.FlagSet) []commandFlag {
	var flags []commandFlag
	fs.VisitAll(func(f *flag.Flag) {
		kind := "value"
		if v, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && v.IsBoolFlag() {
			kind = "bool"
		}
		flags = append(flags, commandFlag{f.Name, f.DefValue, f.Usage, kind, false})
	})
	return flags
}

// Commands outside main.go retain their flag definitions. TestCompletionHelpSync
// checks this static registry against every command's actual --help output.
func commandRegistry() []commandSpec {
	var global globalFlags
	root := flagsFromSet(globalFlagSet(&global))
	scanSet := flag.NewFlagSet("scan", flag.ContinueOnError)
	addScanFlags(scanSet)
	scanFlags := flagsFromSet(scanSet)
	batchFlags := append(append([]commandFlag(nil), scanFlags...), commandFlag{"jobs", "0", "parallel scans (0 = configured concurrency, default 2; 1 = sequential)", "int", false})
	scanFlags = append(scanFlags,
		commandFlag{"cpuprofile", "", "write CPU profile (hidden)", "string", true},
		commandFlag{"memprofile", "", "write heap profile (hidden)", "string", true})
	matchFlags := []commandFlag{
		{"cpuprofile", "", "write CPU profile", "string", true},
		{"memprofile", "", "write heap profile", "string", true},
		{"db", "$BONGSU_HOME/db", "local vulnerability database directory", "string", false},
		{"db-isolation", "auto", "SQLite reader isolation: auto, copy, or none", "string", false},
		{"format", "table", "table, json, cyclonedx, html, markdown, csv, or sarif", "string", false},
		{"o", "", "output file (default stdout)", "string", false},
		{"min-severity", "", "minimum severity to include", "string", false},
		{"fail-on", "", "exit with the findings exit code (default 2, see --findings-exit-code) when a finding meets this severity", "string", false},
		{"ignore", "", "comma-separated advisory IDs to ignore", "string", false},
		{"include-unimportant", "false", "deprecated no-op: unimportant advisories are included by default", "bool", false},
		{"exclude-unimportant", "false", "exclude advisories the distribution rates unimportant or negligible", "bool", false},
		{"severity-source", "distro", "severity policy: cvss, distro, or max", "string", false},
		{"details", "false", "include full advisory details text in findings", "bool", false},
		{"cpe", "false", "enable conservative NVD CPE matching (CPE data can be noisy)", "bool", false},
		{"only-fixed", "false", "include only findings with a known fix", "bool", false},
		{"pubkey", "", "require database signature from trusted name, PEM file, or hex key", "string", false},
		{"llm", "false", "add LLM environment applicability review; retain original findings", "bool", false},
		{"llm-base-url", "$BSCAN_LLM_BASE_URL", "OpenAI-compatible API base URL, e.g. https://server/v1", "string", false},
		{"llm-model", "$BSCAN_LLM_MODEL", "model identifier on the selected LLM server", "string", false},
		{"llm-key-env", "BSCAN_LLM_API_KEY", "environment variable containing the API key", "string", false},
		{"llm-timeout", "1m30s", "timeout per LLM request", "duration", false},
		{"llm-max-findings", "20", "maximum distinct LLM analyses per input SBOM", "int", false},
		{"llm-cache", "$BONGSU_HOME/cache/llm", "LLM cache directory (empty disables caching)", "string", false},
		{"target-os", "", "LLM context OS override, e.g. linux or windows", "string", false},
		{"target-arch", "", "LLM context architecture override, e.g. amd64", "string", false},
		{"env-fact", "", "user-declared LLM context KEY=VALUE (repeatable)", "value", false},
	}
	reportFlags := []commandFlag{
		{"from", "", "required match JSON file (one SBOM)", "string", false},
		{"sbom", "", "SBOM file supplying target and scan metadata", "string", false},
		{"format", "html", "html, markdown (md), json, csv, or sarif", "string", false},
		{"o", "", "output file (default stdout)", "string", false},
		{"title", "", "report target/title override", "string", false},
	}
	updateFlags := []commandFlag{
		{"check", "false", "check without installing", "bool", false},
		{"force", "false", "install even if current", "bool", false},
		{"repo", "ziozzang/bongsu-scanner", "GitHub owner/repository", "string", false},
		{"require-signature", "false", "fail unless SHA256SUMS.sig verifies against a trusted 'release' key", "bool", false},
	}
	dbUpdateFlags := []commandFlag{
		{"add-source", "", "append sources (comma-separated; repeatable; default expands built-ins)", "string", false},
		{"add-ecosystem", "", "append OSV ecosystems and enable osv (comma-separated; repeatable; default expands built-ins)", "string", false},
		{"add-alpine-release", "", "append Alpine releases and enable alpine (comma-separated; repeatable; default expands built-ins)", "string", false},
		{"source", "", "comma-separated sources: osv, alpine, debian, ghsa, nvd (opt-in)", "string", false},
		{"nvd-years", "", "NVD years: range or comma-separated list (default: current year and previous two)", "string", false},
		{"ecosystem", "", "comma-separated OSV ecosystems", "string", false},
		{"alpine-release", "", "comma-separated Alpine releases (e.g. v3.20)", "string", false},
		{"mirror", "", "HTTPS OSV mirror base URL", "string", false},
		{"force", "false", "fetch feeds without conditional request headers", "bool", false},
		{"no-keep-raw", "false", "omit original feeds from installed database", "bool", false},
		{"max-feed-bytes", "1073741824", "maximum bytes per downloaded feed", "int64", false},
		{"max-feed-uncompressed", "17179869184", "maximum total uncompressed bytes per OSV/GHSA archive", "int64", false},
		{"timeout", "30m0s", "overall update timeout", "duration", false},
	}
	scrambleFlags := []commandFlag{
		{"o", "", "output path", "string", false},
		{"chunk-size", "1MiB", "processing chunk size", "string", false},
		{"pubkey", "", "pinned public key for decryption", "string", false},
	}
	checkFlags := []commandFlag{
		{"pubkey", "", "trusted name, public key file, or hex", "string", false},
		{"source", "", "source archive/image for layer manifest verification", "string", false},
	}
	dbBase := commandFlag{"db", "$BONGSU_HOME/db", "database directory", "string", false}
	dbFlags := []commandFlag{dbBase,
		{"db-isolation", "auto", "SQLite reader isolation: auto, copy, or none", "string", false},
		{"pubkey", "", "require signature from trusted name, PEM file, or hex key", "string", false},
	}
	dbUpdateFlags = append(dbUpdateFlags, dbBase)
	commands := []commandSpec{
		{"", "[global flags] COMMAND [command flags] [arguments]", "Embedded host/container SBOM scanner and artifact signer", root},
		{"init", "[flags]", "Initialize configuration and signing identity", []commandFlag{{"signer", "", "signer label", "string", false}}},
		{"config", "show|init", "Inspect or initialize command defaults", nil},
		{"config show", "", "Print effective configuration (file values merged with built-in defaults)", nil},
		{"config init", "", "Create a commented configuration template without replacing an existing file", nil},
		{"key", "show|generate|trust", "Manage signing and trusted keys", nil},
		{"key show", "", "Show local key and fingerprint", nil},
		{"key generate", "", "Ensure a local signing key exists", nil},
		{"key trust", "NAME PUBLIC_KEY", "Register a trusted public key", nil},
		{"scan", "[flags] TARGET", "Scan a host, directory, image, container, or archive", scanFlags},
		{"batch", "[flags] TARGET...", "Scan multiple targets with bounded concurrency", batchFlags},
		{"hash", "[flags] FILE...", "Write a SHA-256 manifest", []commandFlag{{"o", "", "manifest path", "string", false}}},
		{"sign", "[flags] FILE", "Create a detached signature", []commandFlag{{"o", "", "signature path", "string", false}}},
		{"check", "[flags] FILE...", "Verify manifests or signatures", checkFlags},
		{"verify", "[flags] FILE.sig...", "Verify signatures with a trusted key", checkFlags},
		{"scramble", "encrypt|decrypt", "Authenticated reversible scrambling (not confidentiality encryption)", nil},
		{"scramble encrypt", "[flags] FILE", "Scramble and authenticate an artifact", scrambleFlags},
		{"scramble decrypt", "[flags] FILE.bgs", "Verify and restore a scrambled artifact", scrambleFlags},
		{"encrypt", "[flags] FILE", "Alias for scramble encrypt", scrambleFlags},
		{"decrypt", "[flags] FILE.bgs", "Alias for scramble decrypt", scrambleFlags},
		{"db", "update|status|lookup|show|verify|export|import|convert", "Manage the local vulnerability database", nil},
		{"db update", "[flags]", "Download and atomically replace advisory feeds", dbUpdateFlags},
		{"db status", "[flags]", "Show database metadata", dbFlags},
		{"db lookup", "[flags] ECOSYSTEM PACKAGE", "Find advisories for a package", dbFlags},
		{"db show", "[flags] ID", "Show an advisory or CVE alias", dbFlags},
		{"db verify", "[flags]", "Verify database integrity and signatures", dbFlags},
		{"db export", "[flags] FILE.tar.gz", "Export a verified database", dbFlags},
		{"db import", "[flags] FILE.tar.gz", "Import a verified database", dbFlags},
		{"db convert", "[flags] DESTINATION", "Convert a database to SQLite", append(append([]commandFlag(nil), dbFlags...), commandFlag{"no-keep-raw", "false", "omit original downloads from converted database", "bool", false})},
		{"match", "[flags] SBOM...", "Match SBOM packages against local advisories", matchFlags},
		{"report", "[flags]", "Render saved matching results", reportFlags},
		{"update", "[flags]", "Check or install a release", updateFlags},
		{"self-update", "[flags]", "Alias for update", updateFlags},
		{"version", "", "Show version, commit, build date, Go version, platform, and module", nil},
		{"about", "", "Show build information, author, license, and notices", nil},
		{"help", "[COMMAND [SUBCOMMAND]]", "Show command help", nil},
		{"completion", "bash|zsh|fish", "Generate a shell completion script", nil},
		{"completion bash", "", "Generate Bash completion", nil},
		{"completion zsh", "", "Generate Zsh completion", nil},
		{"completion fish", "", "Generate Fish completion", nil},
	}
	for i := range commands {
		commands[i].Flags = append([]commandFlag(nil), commands[i].Flags...)
		sort.Slice(commands[i].Flags, func(a, b int) bool { return commands[i].Flags[a].Name < commands[i].Flags[b].Name })
	}
	return commands
}

// Handle group help before commands that would load config or create keys.
// Leaf commands with FlagSets retain their native help output.
func printCommandHelp(args []string) bool {
	if len(args) == 0 {
		return false
	}
	explicit := args[0] == "help"
	path := ""
	if explicit {
		path = strings.Join(args[1:], " ")
	} else if args[len(args)-1] == "--help" || args[len(args)-1] == "-h" {
		path = strings.Join(args[:len(args)-1], " ")
	} else {
		return false
	}
	for _, command := range commandRegistry() {
		if command.Path != path || (!explicit && len(command.Flags) != 0) {
			continue
		}
		if path == "" {
			usage()
			return true
		}
		fmt.Printf("Usage: bscan %s %s\n\n%s\n", path, command.Arguments, command.Description)
		for _, f := range command.Flags {
			if !f.Hidden {
				fmt.Printf("  --%s (default %q)\n      %s\n", f.Name, f.Default, f.Description)
			}
		}
		return true
	}
	return false
}

func flagSpelling(name string) string {
	if len(name) == 1 {
		return "-" + name
	}
	return "--" + name
}

func completionWords(commands []commandSpec, command commandSpec) []string {
	words := []string{"--help", "-h"}
	for _, f := range command.Flags {
		if !f.Hidden {
			words = append(words, flagSpelling(f.Name))
		}
	}
	for _, child := range commands {
		parent, name, hasParent := strings.Cut(child.Path, " ")
		if child.Path == "" {
			continue
		}
		if command.Path == "" && !hasParent {
			words = append(words, parent)
		} else if hasParent && command.Path == parent {
			words = append(words, name)
		}
	}
	sort.Strings(words)
	return words
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

func cmdCompletion(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: bscan completion bash|zsh|fish")
	}
	return writeCompletion(os.Stdout, args[0])
}

func writeCompletion(w io.Writer, shell string) error {
	if shell != "bash" && shell != "zsh" && shell != "fish" {
		return fmt.Errorf("unsupported completion shell %q (choose bash, zsh, or fish)", shell)
	}
	commands := commandRegistry()
	if shell == "fish" {
		return writeFishCompletion(w, commands)
	}
	var b strings.Builder
	if shell == "zsh" {
		b.WriteString("#compdef bscan\n")
	}
	b.WriteString("# Generated by bscan completion; global flags precede the command.\n_bscan() {\n  local cmdpath='' word pending=0 positional=0 choices='' cur\n  local -a input\n")
	if shell == "bash" {
		b.WriteString("  input=(\"${COMP_WORDS[@]:1:COMP_CWORD-1}\")\n  cur=${COMP_WORDS[COMP_CWORD]}\n  COMPREPLY=()\n")
	} else {
		b.WriteString("  input=(\"${words[@]:1:$((CURRENT-2))}\")\n  cur=${words[CURRENT]}\n")
	}
	b.WriteString("  for word in \"${input[@]}\"; do\n    if (( pending )); then pending=0; continue; fi\n    if (( positional )); then continue; fi\n    case \"$word\" in\n      --) positional=1; continue ;;\n      -*=*) continue ;;\n    esac\n    case \"$cmdpath/$word\" in\n")
	for _, command := range commands {
		for _, f := range command.Flags {
			if f.Kind != "bool" {
				fmt.Fprintf(&b, "      %s|%s) pending=1; continue ;;\n", shellQuote(command.Path+"/-"+f.Name), shellQuote(command.Path+"/--"+f.Name))
			}
		}
	}
	b.WriteString("    esac\n    case \"$word\" in -*) continue ;; esac\n    case \"$cmdpath/$word\" in\n")
	for _, command := range commands {
		if command.Path == "" {
			continue
		}
		parent, name, nested := strings.Cut(command.Path, " ")
		if !nested {
			parent, name = "", parent
		}
		fmt.Fprintf(&b, "      %s) cmdpath=%s ;;\n", shellQuote(parent+"/"+name), shellQuote(command.Path))
	}
	b.WriteString("      *) positional=1 ;;\n    esac\n  done\n  if (( pending || positional )); then\n")
	if shell == "bash" {
		b.WriteString("    return 0 # complete -o default supplies filenames\n")
	} else {
		b.WriteString("    _files; return\n")
	}
	b.WriteString("  fi\n  case \"$cmdpath\" in\n")
	for _, command := range commands {
		fmt.Fprintf(&b, "    %s) choices=%s ;;\n", shellQuote(command.Path), shellQuote(strings.Join(completionWords(commands, command), " ")))
	}
	b.WriteString("  esac\n")
	if shell == "bash" {
		b.WriteString("  while IFS= read -r word; do COMPREPLY+=(\"$word\"); done < <(compgen -W \"$choices\" -- \"$cur\")\n}\ncomplete -o default -F _bscan bscan\n")
	} else {
		b.WriteString("  compadd -- ${=choices}\n  _files\n}\ncompdef _bscan bscan\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func writeFishCompletion(w io.Writer, commands []commandSpec) error {
	var b strings.Builder
	b.WriteString("# Generated by bscan completion fish.\nfunction __bscan_path\n    set -l cmdpath ''\n    set -l pending 0\n    for word in (commandline -opc)[2..-1]\n        if test $pending -eq 1\n            set pending 0\n            continue\n        end\n        switch $word\n            case --\n                echo @files\n                return\n            case '-*=*'\n                continue\n        end\n        switch \"$cmdpath/$word\"\n")
	for _, command := range commands {
		for _, f := range command.Flags {
			if f.Kind != "bool" {
				fmt.Fprintf(&b, "            case %s %s\n                set pending 1\n                continue\n", shellQuote(command.Path+"/-"+f.Name), shellQuote(command.Path+"/--"+f.Name))
			}
		}
	}
	b.WriteString("        end\n        if string match -q -- '-*' $word\n            continue\n        end\n        switch \"$cmdpath/$word\"\n")
	for _, command := range commands {
		if command.Path == "" {
			continue
		}
		parent, name, nested := strings.Cut(command.Path, " ")
		if !nested {
			parent, name = "", parent
		}
		fmt.Fprintf(&b, "            case %s\n                set cmdpath %s\n", shellQuote(parent+"/"+name), shellQuote(command.Path))
	}
	b.WriteString("            case '*'\n                echo @files\n                return\n        end\n    end\n    if test $pending -eq 1\n        echo @files\n    else\n        printf '%s\\n' \"bscan:$cmdpath\"\n    end\nend\ncomplete -c bscan -e\n")
	for _, command := range commands {
		condition := shellQuote("test (__bscan_path) = " + shellQuote("bscan:"+command.Path))
		for _, word := range completionWords(commands, command) {
			if strings.HasPrefix(word, "--") {
				fmt.Fprintf(&b, "complete -c bscan -n %s -l %s", condition, shellQuote(word[2:]))
			} else if strings.HasPrefix(word, "-") {
				fmt.Fprintf(&b, "complete -c bscan -n %s -s %s", condition, shellQuote(word[1:]))
			} else {
				fmt.Fprintf(&b, "complete -c bscan -n %s -a %s", condition, shellQuote(word))
			}
			for _, f := range command.Flags {
				if word == flagSpelling(f.Name) {
					fmt.Fprintf(&b, " -d %s", shellQuote(f.Description))
					if f.Kind != "bool" {
						b.WriteString(" -r")
					}
				}
			}
			b.WriteByte('\n')
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}
