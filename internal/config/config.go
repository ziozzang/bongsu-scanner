// Package config manages ~/.bongsu/scaner.yaml (the requested spelling).
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	Signer      string
	PrivateKey  string
	PublicKey   string
	Hash        string
	Formats     []string
	Concurrency int
	TrustedKeys map[string]string
}

func Defaults() Config {
	return Config{Hash: "sha256", Formats: []string{"spdx", "cyclonedx"}, Concurrency: 2, TrustedKeys: map[string]string{}}
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
	cfg := Defaults()
	path, err := Path()
	if err != nil {
		return cfg, "", err
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return cfg, path, nil
	}
	if err != nil {
		return cfg, path, err
	}
	section := ""
	for n, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimRight(raw, "\r")
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		i := strings.IndexByte(t, ':')
		if i < 1 {
			return cfg, path, fmt.Errorf("%s:%d: expected key: value", path, n+1)
		}
		k, v := strings.TrimSpace(t[:i]), unquote(strings.TrimSpace(strings.SplitN(t[i+1:], " #", 2)[0]))
		indented := line[0] == ' ' || line[0] == '\t'
		if section == "trusted_keys" && indented {
			cfg.TrustedKeys[k] = v
			continue
		}
		section = ""
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
			cfg.Formats = parseList(v)
		case "concurrency":
			cfg.Concurrency, _ = strconv.Atoi(v)
		case "trusted_keys":
			section = k
		}
	}
	if cfg.Concurrency < 1 {
		cfg.Concurrency = 1
	}
	return cfg, path, nil
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
	b.WriteString("trusted_keys:\n")
	for k, v := range cfg.TrustedKeys {
		b.WriteString("  " + quote(k) + ": " + quote(v) + "\n")
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

func unquote(s string) string {
	if len(s) >= 2 && ((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'')) {
		return s[1 : len(s)-1]
	}
	return s
}
func quote(s string) string {
	if s == "" {
		return `""`
	}
	if strings.ContainsAny(s, " :#[],'\"") {
		return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
	}
	return s
}
func parseList(s string) []string {
	s = strings.Trim(s, "[] ")
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		out = append(out, unquote(strings.TrimSpace(p)))
	}
	return out
}
