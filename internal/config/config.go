// Package config manages ~/.bongsu/scaner.yaml (the requested spelling).
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

type Config struct {
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
	return Config{Hash: "sha256", Formats: []string{"spdx", "cyclonedx"}, Concurrency: 2, TrustedKeys: map[string]string{}, SignatureMinVersion: 1}
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
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return cfg, path, warnings, nil
	}
	if err != nil {
		return cfg, path, warnings, err
	}
	section := ""
	mapIndent := 0
	seen := make(map[string]bool)
	for n, raw := range strings.Split(strings.TrimPrefix(string(b), "\ufeff"), "\n") {
		line := strings.TrimSuffix(raw, "\r")
		if !utf8.ValidString(line) {
			return cfg, path, warnings, fmt.Errorf("%s:%d: configuration must be valid UTF-8", path, n+1)
		}
		t := strings.Trim(line, " \t")
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		indented := line[0] == ' ' || line[0] == '\t'
		if indented && section != "trusted_keys" {
			if section == "" {
				return cfg, path, warnings, fmt.Errorf("%s:%d: unexpected indentation", path, n+1)
			}
			// Unknown blocks may contain arbitrary nested mappings and lists.
			continue
		}
		i := keySeparator(t)
		if i < 1 {
			return cfg, path, warnings, fmt.Errorf("%s:%d: expected key: value", path, n+1)
		}
		k, err := unquote(strings.Trim(t[:i], " \t"))
		if err != nil || !printableKey(k) {
			return cfg, path, warnings, fmt.Errorf("%s:%d: invalid configuration key %q (expected printable UTF-8 scalar)", path, n+1, t[:i])
		}
		rawValue := strings.TrimSpace(stripComment(strings.TrimSpace(t[i+1:])))
		if section == "trusted_keys" && indented {
			indent := len(line) - len(strings.TrimLeft(line, " \t"))
			if mapIndent != 0 && indent != mapIndent {
				return cfg, path, warnings, fmt.Errorf("%s:%d: trusted_keys must be a flat map", path, n+1)
			}
			mapIndent = indent
			v, err := scalar(rawValue)
			if err != nil || rawValue == "" {
				return cfg, path, warnings, fmt.Errorf("%s:%d: trusted_keys[%q]: expected scalar value; inline maps/flow sequences and nested blocks are unsupported", path, n+1, k)
			}
			if _, exists := cfg.TrustedKeys[k]; exists {
				warnings = append(warnings, fmt.Sprintf("%s:%d: duplicate trusted_keys key %q; last value wins", path, n+1, k))
			}
			cfg.TrustedKeys[k] = v
			continue
		}
		section = ""
		mapIndent = 0
		if seen[k] {
			warnings = append(warnings, fmt.Sprintf("%s:%d: duplicate configuration key %q; last value wins", path, n+1, k))
		}
		seen[k] = true
		// Unknown keys keep their warning-only behavior, including unknown blocks.
		switch k {
		case "signer", "private_key", "key_path", "public_key", "hash", "formats", "concurrency", "offline", "db_require_signature", "update_require_signature", "signature_min_version", "trusted_keys":
		default:
			section = k
			warnings = append(warnings, fmt.Sprintf("%s:%d: unknown configuration key %q; key and any nested block ignored", path, n+1, k))
			continue
		}
		v := rawValue
		if k != "formats" {
			v, err = scalar(rawValue)
			if err != nil {
				return cfg, path, warnings, fmt.Errorf("%s:%d: %s: %w", path, n+1, k, err)
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
				return cfg, path, warnings, fmt.Errorf("%s:%d: formats: %w", path, n+1, err)
			}
		case "concurrency":
			cfg.Concurrency, _ = strconv.Atoi(v)
		case "offline", "db_require_signature", "update_require_signature":
			value, err := parseBool(v)
			if err != nil {
				return cfg, path, warnings, fmt.Errorf("%s:%d: %s: %w", path, n+1, k, err)
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
				return cfg, path, warnings, fmt.Errorf("%s:%d: signature_min_version must be 1 or 2", path, n+1)
			}
			cfg.SignatureMinVersion = minimum
		case "trusted_keys":
			if rawValue != "" {
				return cfg, path, warnings, fmt.Errorf("%s:%d: trusted_keys must be a block map; inline maps/flow sequences are unsupported", path, n+1)
			}
			cfg.TrustedKeys = make(map[string]string)
			section = k
		}
	}
	if cfg.Concurrency < 1 {
		cfg.Concurrency = 1
	}
	return cfg, path, warnings, nil
}

func Save(cfg Config) error {
	path, err := Path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("# bongsu scanner configuration\n")
	b.WriteString("signer: " + quote(cfg.Signer) + "\n")
	b.WriteString("private_key: " + quote(cfg.PrivateKey) + "\n")
	b.WriteString("public_key: " + quote(cfg.PublicKey) + "\n")
	b.WriteString("hash: " + quote(cfg.Hash) + "\n")
	b.WriteString("formats: [" + strings.Join(cfg.Formats, ", ") + "]\n")
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
	return os.WriteFile(path, []byte(b.String()), 0o600)
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
