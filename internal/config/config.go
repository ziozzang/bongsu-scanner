// Package config manages ~/.bongsu/scaner.yaml (the requested spelling).
package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ScanConfig, MatchConfig and DBConfig provide defaults for command flags.
type ScanConfig struct {
	Excludes        []string
	OneFileSystem   bool
	Workers         int
	RedactIP        bool
	NoHostMetadata  bool
	SkipBinaries    bool
	IncludeDeclared bool
	Containers      bool
	FailOnPartial   bool
	Output          string
	Format          string
}
type MatchConfig struct {
	SeveritySource     string
	ExcludeUnimportant bool
	MinSeverity        string
	FailOn             string
	OnlyFixed          bool
	DBIsolation        string
	ReportFormats      []string
}
type DBConfig struct {
	Sources             []string
	Ecosystems          []string
	AlpineReleases      []string
	NVDYears            string
	MaxFeedBytes        int64
	MaxFeedUncompressed int64
	KeepRaw             bool
	Mirror              string
}

type Config struct {
	Scan        ScanConfig
	Match       MatchConfig
	DB          DBConfig
	Signer      string
	PrivateKey  string
	PublicKey   string
	Hash        string
	Formats     []string
	Concurrency int
	TrustedKeys map[string]string
	// Offline disables every outbound network access (update checks and, in
	// future, database refreshes). Equivalent to BONGSU_OFFLINE=1.
	Offline bool `yaml:"offline" json:"offline"`
	// DBRequireSignature and UpdateRequireSignature require trusted signatures
	// for database refreshes and self-updates, respectively, for CLI consumers.
	DBRequireSignature     bool `yaml:"db_require_signature" json:"db_require_signature"`
	UpdateRequireSignature bool `yaml:"update_require_signature" json:"update_require_signature"`
	// SignatureMinVersion is the oldest accepted signature format (1 or 2).
	SignatureMinVersion int `yaml:"signature_min_version" json:"signature_min_version"`
}

func Defaults() Config {
	return Config{Scan: ScanConfig{Output: ".", Format: "both"}, Match: MatchConfig{SeveritySource: "distro", DBIsolation: "auto"}, DB: DBConfig{MaxFeedBytes: 1 << 30, MaxFeedUncompressed: 16 << 30, KeepRaw: true}, Hash: "sha256", Formats: []string{"spdx", "cyclonedx"}, Concurrency: 2, TrustedKeys: map[string]string{}, SignatureMinVersion: 1}
}

// CheckSignatureVersion applies the configured minimum before a caller verifies
// a record. Zero keeps the default for callers constructing Config directly.
func (c Config) CheckSignatureVersion(version int) error {
	minimum := c.SignatureMinVersion
	if minimum == 0 {
		minimum = 1
	}
	if minimum != 1 && minimum != 2 {
		return fmt.Errorf("signature_min_version must be 1 or 2")
	}
	if version < minimum {
		return fmt.Errorf("signature version %d is below signature_min_version %d", version, minimum)
	}
	return nil
}

func Dir() (string, error) {
	if d := strings.TrimSpace(os.Getenv("BONGSU_HOME")); d != "" {
		return d, nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, ".bongsu"), nil
}

func Path() (string, error) {
	d, err := Dir()
	return filepath.Join(d, "scaner.yaml"), err
}

func Expand(path string) (string, error) {
	path = strings.TrimSpace(path)
	d, err := Dir()
	if err != nil {
		return "", err
	}
	if path == "" {
		return filepath.Join(d, "signing.key"), nil
	}
	if path == "~" || strings.HasPrefix(path, "~/") {
		h, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		if path == "~" {
			return h, nil
		}
		return filepath.Join(h, path[2:]), nil
	}
	if filepath.IsAbs(path) {
		return path, nil
	}
	return filepath.Join(d, path), nil
}

func Load() (Config, string, error) {
	cfg, path, _, err := LoadWithWarnings()
	return cfg, path, err
}

// LoadForCLI loads configuration and prints its warnings to standard error.
// Library consumers can use Load or LoadWithWarnings to stay silent.
func LoadForCLI() (Config, string, error) {
	cfg, path, warnings, err := LoadWithWarnings()
	for _, warning := range warnings {
		fmt.Fprintln(os.Stderr, "warning: "+warning)
	}
	return cfg, path, err
}

// LoadWithWarnings loads the configuration and returns warnings for ignored
// unknown top-level keys or blocks, and duplicate keys (last value wins).
// Neither it nor Load prints diagnostics.
func LoadWithWarnings() (Config, string, []string, error) {
	cfg := Defaults()
	var warnings []string
	path, err := Path()
	if err != nil {
		return cfg, "", warnings, err
	}
	b, err := os.ReadFile(path) // #nosec G304 -- Local CLI/API paths are caller-selected; reading or writing arbitrary local paths is intentional.
	if os.IsNotExist(err) {
		return cfg, path, warnings, nil
	}
	if err != nil {
		return cfg, path, warnings, err
	}
	cfg, warnings, err = parse(path, b)
	return cfg, path, warnings, err
}

// parse decodes the configuration text. path only labels diagnostics; the
// returned Config starts from Defaults and is complete even when err != nil.
func parse(path string, b []byte) (Config, []string, error) {
	cfg := Defaults()
	var warnings []string
	section := ""
	mapIndent := 0
	listKey := ""
	ignoredIndent := 0
	seen := make(map[string]bool)
	for n, raw := range strings.Split(strings.TrimPrefix(string(b), "\ufeff"), "\n") {
		line := strings.TrimSuffix(raw, "\r")
		if !utf8.ValidString(line) {
			return cfg, warnings, fmt.Errorf("%s:%d: configuration must be valid UTF-8", path, n+1)
		}
		t := strings.Trim(line, " \t")
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		indented := line[0] == ' ' || line[0] == '\t'
		if indented && optionBlock(section) {
			indent := len(line) - len(strings.TrimLeft(line, " \t"))
			if ignoredIndent != 0 && indent > ignoredIndent {
				continue
			}
			ignoredIndent = 0
			if listKey != "" && indent > mapIndent {
				if !strings.HasPrefix(t, "- ") && t != "-" {
					return cfg, warnings, fmt.Errorf("%s:%d: %s.%s: expected list item", path, n+1, section, listKey)
				}
				rawItem := strings.TrimSpace(stripComment(strings.TrimSpace(strings.TrimPrefix(t, "-"))))
				value, err := scalar(rawItem)
				if err != nil || rawItem == "" {
					return cfg, warnings, fmt.Errorf("%s:%d: %s.%s: expected scalar list item", path, n+1, section, listKey)
				}
				dest := optionValue(&cfg, section, listKey).(*[]string)
				*dest = append(*dest, value)
				continue
			}
			listKey = ""
			if mapIndent != 0 && indent != mapIndent {
				return cfg, warnings, fmt.Errorf("%s:%d: %s must be a flat map with scalar or list values", path, n+1, section)
			}
			mapIndent = indent
			i := keySeparator(t)
			if i < 1 {
				return cfg, warnings, fmt.Errorf("%s:%d: expected key: value", path, n+1)
			}
			k, err := unquote(strings.TrimSpace(t[:i]))
			if err != nil || !printableKey(k) {
				return cfg, warnings, fmt.Errorf("%s:%d: invalid configuration key", path, n+1)
			}
			name := section + "." + k
			dest := optionValue(&cfg, section, k)
			if dest == nil {
				warnings = append(warnings, fmt.Sprintf("%s:%d: unknown configuration key %q; key and any nested block ignored", path, n+1, name))
				ignoredIndent = indent
				continue
			}
			if seen[name] {
				warnings = append(warnings, fmt.Sprintf("%s:%d: duplicate configuration key %q; last value wins", path, n+1, name))
			}
			seen[name] = true
			rawValue := strings.TrimSpace(stripComment(strings.TrimSpace(t[i+1:])))
			if list, ok := dest.(*[]string); ok && rawValue == "" {
				*list = nil
				listKey = k
				continue
			}
			if err := parseOption(dest, rawValue); err != nil {
				return cfg, warnings, fmt.Errorf("%s:%d: %s: %w", path, n+1, name, err)
			}
			continue
		}
		if indented && section != "trusted_keys" {
			if section == "" {
				return cfg, warnings, fmt.Errorf("%s:%d: unexpected indentation", path, n+1)
			}
			// Unknown blocks may contain arbitrary nested mappings and lists.
			continue
		}
		i := keySeparator(t)
		if i < 1 {
			return cfg, warnings, fmt.Errorf("%s:%d: expected key: value", path, n+1)
		}
		k, err := unquote(strings.Trim(t[:i], " \t"))
		if err != nil || !printableKey(k) {
			return cfg, warnings, fmt.Errorf("%s:%d: invalid configuration key %q (expected printable UTF-8 scalar)", path, n+1, t[:i])
		}
		rawValue := strings.TrimSpace(stripComment(strings.TrimSpace(t[i+1:])))
		if section == "trusted_keys" && indented {
			indent := len(line) - len(strings.TrimLeft(line, " \t"))
			if mapIndent != 0 && indent != mapIndent {
				return cfg, warnings, fmt.Errorf("%s:%d: trusted_keys must be a flat map", path, n+1)
			}
			mapIndent = indent
			v, err := scalar(rawValue)
			if err != nil || rawValue == "" {
				return cfg, warnings, fmt.Errorf("%s:%d: trusted_keys[%q]: expected scalar value; inline maps/flow sequences and nested blocks are unsupported", path, n+1, k)
			}
			if _, exists := cfg.TrustedKeys[k]; exists {
				warnings = append(warnings, fmt.Sprintf("%s:%d: duplicate trusted_keys key %q; last value wins", path, n+1, k))
			}
			cfg.TrustedKeys[k] = v
			continue
		}
		section = ""
		listKey = ""
		ignoredIndent = 0
		mapIndent = 0
		if seen[k] {
			warnings = append(warnings, fmt.Sprintf("%s:%d: duplicate configuration key %q; last value wins", path, n+1, k))
		}
		seen[k] = true
		// Unknown keys keep their warning-only behavior, including unknown blocks.
		switch k {
		case "signer", "private_key", "key_path", "public_key", "hash", "formats", "concurrency", "offline", "db_require_signature", "update_require_signature", "signature_min_version", "trusted_keys", "scan", "match", "db":
		default:
			section = k
			warnings = append(warnings, fmt.Sprintf("%s:%d: unknown configuration key %q; key and any nested block ignored", path, n+1, k))
			continue
		}
		v := rawValue
		if k != "formats" {
			v, err = scalar(rawValue)
			if err != nil {
				return cfg, warnings, fmt.Errorf("%s:%d: %s: %w", path, n+1, k, err)
			}
		}
		switch k {
		case "signer":
			cfg.Signer = v
		case "private_key", "key_path":
			cfg.PrivateKey = v
		case "public_key":
			cfg.PublicKey = v
		case "hash":
			cfg.Hash = v
		case "formats":
			cfg.Formats, err = parseList(v)
			if err != nil {
				return cfg, warnings, fmt.Errorf("%s:%d: formats: %w", path, n+1, err)
			}
		case "concurrency":
			cfg.Concurrency, _ = strconv.Atoi(v)
		case "offline", "db_require_signature", "update_require_signature":
			value, err := parseBool(v)
			if err != nil {
				return cfg, warnings, fmt.Errorf("%s:%d: %s: %w", path, n+1, k, err)
			}
			switch k {
			case "offline":
				cfg.Offline = value
			case "db_require_signature":
				cfg.DBRequireSignature = value
			case "update_require_signature":
				cfg.UpdateRequireSignature = value
			}
		case "signature_min_version":
			minimum, err := strconv.Atoi(v)
			if err != nil || (minimum != 1 && minimum != 2) {
				return cfg, warnings, fmt.Errorf("%s:%d: signature_min_version must be 1 or 2", path, n+1)
			}
			cfg.SignatureMinVersion = minimum
		case "scan", "match", "db":
			if rawValue != "" {
				return cfg, warnings, fmt.Errorf("%s:%d: %s must be a block map", path, n+1, k)
			}
			defaults := Defaults()
			switch k {
			case "scan":
				cfg.Scan = defaults.Scan
			case "match":
				cfg.Match = defaults.Match
			case "db":
				cfg.DB = defaults.DB
			}
			for name := range seen {
				if strings.HasPrefix(name, k+".") {
					delete(seen, name)
				}
			}
			section = k
		case "trusted_keys":
			if rawValue != "" {
				return cfg, warnings, fmt.Errorf("%s:%d: trusted_keys must be a block map; inline maps/flow sequences are unsupported", path, n+1)
			}
			cfg.TrustedKeys = make(map[string]string)
			section = k
		}
	}
	if cfg.Concurrency < 1 {
		cfg.Concurrency = 1
	}
	return cfg, warnings, nil
}

func Save(cfg Config) error {
	path, err := Path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, render(cfg), 0o600)
}

// render produces the configuration text Save writes; parse reads it back
// to an equal Config.
func render(cfg Config) []byte {
	var b strings.Builder
	b.WriteString("# bongsu scanner configuration\n")
	b.WriteString("signer: " + quote(cfg.Signer) + "\n")
	b.WriteString("private_key: " + quote(cfg.PrivateKey) + "\n")
	b.WriteString("public_key: " + quote(cfg.PublicKey) + "\n")
	b.WriteString("hash: " + quote(cfg.Hash) + "\n")
	formats := make([]string, 0, len(cfg.Formats))
	for _, f := range cfg.Formats {
		formats = append(formats, listItem(f))
	}
	b.WriteString("formats: [" + strings.Join(formats, ", ") + "]\n")
	b.WriteString("concurrency: " + strconv.Itoa(cfg.Concurrency) + "\n")
	b.WriteString("offline: " + strconv.FormatBool(cfg.Offline) + "\n")
	b.WriteString("db_require_signature: " + strconv.FormatBool(cfg.DBRequireSignature) + "\n")
	b.WriteString("update_require_signature: " + strconv.FormatBool(cfg.UpdateRequireSignature) + "\n")
	minimum := cfg.SignatureMinVersion
	if minimum == 0 {
		minimum = 1
	}
	b.WriteString("signature_min_version: " + strconv.Itoa(minimum) + "\n")
	b.WriteString("trusted_keys:\n")
	for k, v := range cfg.TrustedKeys {
		b.WriteString("  " + quote(k) + ": " + quote(v) + "\n")
	}
	for _, section := range []string{"scan", "match", "db"} {
		b.WriteString("# Defaults for " + section + " command flags; explicit CLI flags take precedence.\n")
		b.WriteString(section + ":\n")
		for _, field := range optionFields(&cfg, section) {
			var value string
			switch p := field.value.(type) {
			case *string:
				value = quote(*p)
			case *bool:
				value = strconv.FormatBool(*p)
			case *int:
				value = strconv.Itoa(*p)
			case *int64:
				value = strconv.FormatInt(*p, 10)
			case *[]string:
				items := make([]string, len(*p))
				for i, item := range *p {
					items[i] = quote(item)
				}
				value = "[" + strings.Join(items, ", ") + "]"
			}
			b.WriteString("  " + field.name + ": " + value + "\n")
		}
	}
	return []byte(b.String())
}

// Marshal returns the effective configuration in the supported YAML subset.
func Marshal(cfg Config) []byte { return render(cfg) }

// MarshalDisplay masks mirror credentials in a copy, leaving persistence exact.
func MarshalDisplay(cfg Config) []byte {
	if cfg.DB.Mirror != "" {
		cfg.DB.Mirror = displayMirror(cfg.DB.Mirror)
	}
	return render(cfg)
}

func displayMirror(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" {
		return "[REDACTED]"
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "[REDACTED]"
	}
	changed := false
	if u.User != nil {
		if _, hasPassword := u.User.Password(); hasPassword {
			u.User = url.UserPassword("REDACTED", "REDACTED")
		} else {
			u.User = url.User("REDACTED")
		}
		changed = true
	}
	queryChanged := false
	for key := range query {
		switch strings.ToLower(key) {
		case "token", "key", "sig", "signature", "password":
			query.Set(key, "REDACTED")
			queryChanged = true
		}
	}
	if queryChanged {
		u.RawQuery = query.Encode()
	}
	if changed || queryChanged {
		return u.String()
	}
	return raw
}

// InitTemplate creates a commented default configuration without replacing an
// existing file or generating a signing identity.
func InitTemplate() (string, error) {
	path, err := Path()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return path, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- Local CLI/API paths are caller-selected; reading or writing arbitrary local paths is intentional.
	if err != nil {
		return path, err
	}
	_, writeErr := f.Write(render(Defaults()))
	closeErr := f.Close()
	if writeErr != nil {
		return path, writeErr
	}
	return path, closeErr
}

type optionField struct {
	name  string
	value any
}

func optionBlock(s string) bool { return s == "scan" || s == "match" || s == "db" }
func optionFields(c *Config, section string) []optionField {
	switch section {
	case "scan":
		return []optionField{
			{"excludes", &c.Scan.Excludes}, {"one_file_system", &c.Scan.OneFileSystem}, {"workers", &c.Scan.Workers},
			{"redact_ip", &c.Scan.RedactIP}, {"no_host_metadata", &c.Scan.NoHostMetadata}, {"skip_binaries", &c.Scan.SkipBinaries},
			{"include_declared", &c.Scan.IncludeDeclared}, {"containers", &c.Scan.Containers}, {"fail_on_partial", &c.Scan.FailOnPartial},
			{"output", &c.Scan.Output}, {"format", &c.Scan.Format},
		}
	case "match":
		return []optionField{
			{"severity_source", &c.Match.SeveritySource}, {"exclude_unimportant", &c.Match.ExcludeUnimportant},
			{"min_severity", &c.Match.MinSeverity}, {"fail_on", &c.Match.FailOn}, {"only_fixed", &c.Match.OnlyFixed},
			{"db_isolation", &c.Match.DBIsolation}, {"report_formats", &c.Match.ReportFormats},
		}
	case "db":
		return []optionField{
			{"sources", &c.DB.Sources}, {"ecosystems", &c.DB.Ecosystems}, {"alpine_releases", &c.DB.AlpineReleases},
			{"nvd_years", &c.DB.NVDYears}, {"max_feed_bytes", &c.DB.MaxFeedBytes}, {"max_feed_uncompressed", &c.DB.MaxFeedUncompressed},
			{"keep_raw", &c.DB.KeepRaw}, {"mirror", &c.DB.Mirror},
		}
	}
	return nil
}
func optionValue(c *Config, section, key string) any {
	for _, field := range optionFields(c, section) {
		if field.name == key {
			return field.value
		}
	}
	return nil
}
func parseOption(dest any, raw string) error {
	if p, ok := dest.(*[]string); ok {
		value, err := parseOptionList(raw)
		if err == nil {
			*p = value
		}
		return err
	}
	value, err := scalar(raw)
	if err != nil {
		return err
	}
	switch p := dest.(type) {
	case *string:
		*p = value
	case *bool:
		*p, err = parseBool(value)
	case *int:
		*p, err = strconv.Atoi(value)
	case *int64:
		*p, err = strconv.ParseInt(value, 10, 64)
	}
	return err
}

// Unlike legacy formats, command lists require YAML sequence syntax. Split only
// on commas outside quotes so paths containing punctuation round-trip intact.
func parseOptionList(raw string) ([]string, error) {
	if !strings.HasPrefix(raw, "[") || !strings.HasSuffix(raw, "]") {
		return nil, fmt.Errorf("expected list [value, ...] or indented list items")
	}
	body := strings.TrimSpace(raw[1 : len(raw)-1])
	if body == "" {
		return nil, nil
	}
	var result []string
	var quoted byte
	start := 0
	for i := 0; i <= len(body); i++ {
		if i == len(body) || (body[i] == ',' && quoted == 0) {
			part := strings.TrimSpace(body[start:i])
			if part == "" {
				return nil, fmt.Errorf("empty list item")
			}
			value, err := scalar(part)
			if err != nil {
				return nil, err
			}
			result = append(result, value)
			start = i + 1
			continue
		}
		c := body[i]
		if quoted != 0 {
			if quoted == '"' && c == '\\' {
				i++
			} else if c == quoted {
				if quoted == '\'' && i+1 < len(body) && body[i+1] == '\'' {
					i++
				} else {
					quoted = 0
				}
			}
		} else if (c == '"' || c == '\'') && strings.TrimSpace(body[start:i]) == "" {
			quoted = c
		}
	}
	if quoted != 0 {
		return nil, fmt.Errorf("unterminated quoted list item")
	}
	return result, nil
}

// listItem keeps ordinary format names bare ("[spdx, cyclonedx]") and quotes
// anything the flow-sequence reader would otherwise split, trim or treat as
// a comment.
func listItem(s string) string {
	if s == "" || strings.ContainsAny(s, ",[]\"'#: \t\\") || strings.TrimSpace(s) != s {
		return quote(s)
	}
	return s
}

func unquote(s string) (string, error) {
	if strings.HasPrefix(s, `"`) {
		return strconv.Unquote(s)
	}
	if strings.HasPrefix(s, "'") {
		if len(s) < 2 || s[len(s)-1] != '\'' {
			return "", fmt.Errorf("unterminated single-quoted scalar")
		}
		inner := s[1 : len(s)-1]
		if strings.ContainsRune(strings.ReplaceAll(inner, "''", ""), '\'') {
			return "", fmt.Errorf("single quotes must be doubled inside a single-quoted scalar")
		}
		return strings.ReplaceAll(inner, "''", "'"), nil
	}
	return s, nil
}
func quote(s string) string {
	return strconv.Quote(s)
}

func printableKey(s string) bool {
	if s == "" || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// keySeparator finds the first colon outside a quoted key. Quotes in plain
// keys (such as O'Brien) are literal, as they are in plain values.
func keySeparator(s string) int {
	var quoted byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quoted != 0 {
			if quoted == '"' && c == '\\' {
				i++
			} else if c == quoted {
				if quoted == '\'' && i+1 < len(s) && s[i+1] == '\'' {
					i++
				} else {
					quoted = 0
				}
			}
		} else if c == ':' {
			return i
		} else if i == 0 && (c == '"' || c == '\'') {
			quoted = c
		}
	}
	return -1
}

func scalar(s string) (string, error) {
	if strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[") {
		return "", fmt.Errorf("inline maps/flow sequences are unsupported here; expected a scalar")
	}
	return unquote(s)
}

// stripComment preserves hashes inside quoted scalars, including escaped quotes.
func stripComment(s string) string {
	var quoted byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quoted != 0 {
			if quoted == '"' && c == '\\' {
				i++
			} else if c == quoted {
				if quoted == '\'' && i+1 < len(s) && s[i+1] == '\'' {
					i++
				} else {
					quoted = 0
				}
			}
			continue
		}
		if c == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t') {
			return s[:i]
		}
		if (c == '"' || c == '\'') && (i == 0 || strings.ContainsRune(" \t[,", rune(s[i-1]))) {
			quoted = c
		}
	}
	return s
}

func parseBool(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	}
	return false, fmt.Errorf("invalid boolean %q (expected true/false/yes/no/on/off/1/0)", s)
}
func parseList(s string) ([]string, error) {
	var err error
	s, err = unquote(s)
	if err != nil {
		return nil, err
	}
	s = strings.Trim(s, "[] ")
	if s == "" {
		return nil, nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		v, err := scalar(strings.TrimSpace(p))
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
