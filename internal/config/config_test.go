package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestSaveLoad(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	want := Defaults()
	want.Signer = "ziozzang@gmail.com"
	want.PrivateKey = "private key.pem"
	want.TrustedKeys["release"] = "abcdef"
	if err := Save(want); err != nil {
		t.Fatal(err)
	}
	got, path, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.Signer != want.Signer || got.PrivateKey != want.PrivateKey || got.TrustedKeys["release"] != "abcdef" {
		t.Fatalf("round trip = %#v", got)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("config permissions: %v %#o", err, info.Mode().Perm())
	}
	if filepath.Base(path) != "scaner.yaml" {
		t.Fatalf("path = %s", path)
	}
}

func TestOfflineRoundTrip(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	if Defaults().Offline {
		t.Fatal("offline must default to false")
	}
	want := Defaults()
	want.Offline = true
	if err := Save(want); err != nil {
		t.Fatal(err)
	}
	got, _, err := Load()
	if err != nil || !got.Offline {
		t.Fatalf("round trip offline: %v %#v", err, got)
	}
}

func TestOfflineParsing(t *testing.T) {
	for value, want := range map[string]bool{
		"true": true, "yes": true, "on": true, "1": true, "True": true, `"true"`: true, "true # comment": true,
		"false": false, "no": false, "off": false, "0": false, "FALSE": false,
	} {
		dir := t.TempDir()
		t.Setenv("BONGSU_HOME", dir)
		if err := os.WriteFile(filepath.Join(dir, "scaner.yaml"), []byte("signer: x\noffline: "+value+"\nconcurrency: 2\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, _, err := Load()
		if err != nil {
			t.Fatalf("offline: %s: %v", value, err)
		}
		if got.Offline != want {
			t.Errorf("offline: %q parsed as %t, want %t", value, got.Offline, want)
		}
		if got.Signer != "x" || got.Concurrency != 2 {
			t.Errorf("offline: %q disturbed other keys: %#v", value, got)
		}
	}
}

func TestSecurityConfigParsing(t *testing.T) {
	for _, tc := range []struct {
		name, input             string
		offline                 bool
		signer, release, errKey string
	}{
		{name: "tab comment", input: "offline: true\t# comment\n", offline: true},
		{name: "quoted key", input: "\"offline\": true\n", offline: true},
		{name: "single quoted key", input: "'offline': yes\n", offline: true},
		{name: "quoted map keys", input: "\"trusted_keys\":\n  \"release\": abcdef\n", release: "abcdef"},
		{name: "single quoted map keys", input: "'trusted_keys':\n  'release': abcdef\n", release: "abcdef"},
		{name: "nested offline", input: "offline: true\nllm:\n  offline: false\n", offline: true},
		{name: "ignore whole block", input: "offline: true\nllm:\n  nested:\n    offline: false\n  - list item\n  malformed\nsigner: after\n", offline: true, signer: "after"},
		{name: "nested trusted keys", input: "llm:\n  trusted_keys:\n    release: attacker\n"},
		{name: "quoted space hash", input: "signer: \"name # literal\" # comment\n", signer: "name # literal"},
		{name: "quoted tab hash", input: "signer: 'name\t# literal'\t# comment\n", signer: "name\t# literal"},
		{name: "unspaced hash", input: "signer: name#literal\n", signer: "name#literal"},
		{name: "apostrophe in plain scalar", input: "signer: O'Brien # comment\n", signer: "O'Brien"},
		{name: "invalid boolean", input: "offline: maybe\n", errKey: "offline"},
		{name: "empty boolean", input: "offline:\n", errKey: "offline"},
		{name: "unsupported boolean", input: "offline: y\n", errKey: "offline"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("BONGSU_HOME", dir)
			path := filepath.Join(dir, "scaner.yaml")
			if err := os.WriteFile(path, []byte(tc.input), 0o600); err != nil {
				t.Fatal(err)
			}
			got, _, err := Load()
			if tc.errKey != "" {
				if err == nil || !strings.Contains(err.Error(), tc.errKey) || !strings.Contains(err.Error(), path+":1:") {
					t.Fatalf("expected located error for %s, got %v", tc.errKey, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Offline != tc.offline || got.Signer != tc.signer || got.TrustedKeys["release"] != tc.release {
				t.Fatalf("unexpected configuration: %#v", got)
			}
		})
	}
}

func TestLoadWithWarnings(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		warnings    []string
	}{
		{"known keys", "offline: true\ntrusted_keys:\n  release: abc\n", nil},
		{"unknown scalar", "offlien: true\noffline: true\n", []string{`unknown configuration key "offlien"`}},
		{"unknown block", "llm:\n  offline: false\n  unknown: value\noffline: true\n", []string{`unknown configuration key "llm"`}},
		{"quoted unknown block", "'llm':\n\n  # comment\n  offline: false\noffline: true\n", []string{`unknown configuration key "llm"`}},
		{"multiple unknown keys", "llm:\n  offline: false\nother: value\noffline: true\n", []string{`unknown configuration key "llm"`, `unknown configuration key "other"`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("BONGSU_HOME", dir)
			path := filepath.Join(dir, "scaner.yaml")
			if err := os.WriteFile(path, []byte(tc.input), 0o600); err != nil {
				t.Fatal(err)
			}
			got, gotPath, warnings, err := LoadWithWarnings()
			if err != nil || gotPath != path || !got.Offline || len(warnings) != len(tc.warnings) {
				t.Fatalf("cfg=%#v path=%q warnings=%v err=%v", got, gotPath, warnings, err)
			}
			for i, want := range tc.warnings {
				if !strings.Contains(warnings[i], want) || !strings.HasPrefix(warnings[i], path+":") {
					t.Errorf("warning %q, want %q with path", warnings[i], want)
				}
			}
		})
	}
}

func TestSignaturePolicyParsingAndSave(t *testing.T) {
	for _, key := range []string{"db_require_signature", "update_require_signature"} {
		for value, want := range map[string]bool{
			"true": true, "YES": true, "On": true, "1": true,
			"false": false, "NO": false, "Off": false, "0": false,
		} {
			t.Run(key+"/"+value, func(t *testing.T) {
				dir := t.TempDir()
				t.Setenv("BONGSU_HOME", dir)
				path := filepath.Join(dir, "scaner.yaml")
				if err := os.WriteFile(path, []byte(key+": "+value+"\t# policy\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				cfg, _, warnings, err := LoadWithWarnings()
				if err != nil || len(warnings) != 0 {
					t.Fatalf("warnings=%v err=%v", warnings, err)
				}
				got := cfg.DBRequireSignature
				if key == "update_require_signature" {
					got = cfg.UpdateRequireSignature
				}
				if got != want {
					t.Fatalf("%s=%t, want %t", key, got, want)
				}
				if err := Save(cfg); err != nil {
					t.Fatal(err)
				}
				b, err := os.ReadFile(path)
				if err != nil || !strings.Contains(string(b), key+": "+strconv.FormatBool(want)+"\n") {
					t.Fatalf("saved config=%s err=%v", b, err)
				}
				reloaded, _, err := Load()
				if err != nil || reloaded.DBRequireSignature != cfg.DBRequireSignature || reloaded.UpdateRequireSignature != cfg.UpdateRequireSignature {
					t.Fatalf("round trip=%#v err=%v", reloaded, err)
				}
			})
		}
		for _, value := range []string{"", "maybe", "y", "n", "2", "true#comment"} {
			t.Run(key+"/invalid/"+value, func(t *testing.T) {
				dir := t.TempDir()
				t.Setenv("BONGSU_HOME", dir)
				if err := os.WriteFile(filepath.Join(dir, "scaner.yaml"), []byte(key+": "+value+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if _, _, err := Load(); err == nil || !strings.Contains(err.Error(), key) {
					t.Fatalf("err=%v", err)
				}
			})
		}
	}
	if cfg := Defaults(); cfg.DBRequireSignature || cfg.UpdateRequireSignature {
		t.Fatal("signature policies must default to false")
	}
}

func TestLoadDoesNotPrintWarnings(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BONGSU_HOME", dir)
	if err := os.WriteFile(filepath.Join(dir, "scaner.yaml"), []byte("unknown: value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	stdout, stderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = output, output
	defer func() { os.Stdout, os.Stderr = stdout, stderr }()
	if _, _, err := Load(); err != nil {
		t.Fatal(err)
	}
	info, err := output.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatal("Load printed diagnostics")
	}
}

func TestLoadBOMAndCRLF(t *testing.T) {
	for _, body := range []string{
		"offline: true\r\nupdate_require_signature: true\r\ndb_require_signature: true\r\ntrusted_keys:\r\n  release: abc\r\n",
		"trusted_keys:\r\n  release: abc\r\noffline: true\r\nupdate_require_signature: true\r\ndb_require_signature: true\r\n",
	} {
		t.Setenv("BONGSU_HOME", t.TempDir())
		path, _ := Path()
		if err := os.WriteFile(path, []byte("\ufeff"+body), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, _, warnings, err := LoadWithWarnings()
		if err != nil || len(warnings) != 0 || !cfg.Offline || !cfg.UpdateRequireSignature || !cfg.DBRequireSignature || cfg.TrustedKeys["release"] != "abc" {
			t.Fatalf("cfg=%#v warnings=%v err=%v", cfg, warnings, err)
		}
	}
}

func TestLoadRejectsMalformedSecurityConfiguration(t *testing.T) {
	for _, body := range []string{
		"off\x00line: true", "\x1boffline: true", "offline\u200b: true", "offline\xff: true", "offline\r: true",
		`"off\u0000line": true`, `"offline": "true`, `offline: "tr\que"`,
		"\ufeff\ufeffoffline: true", "\xff\xfeo\x00f\x00f\x00l\x00i\x00n\x00e\x00:\x00",
		"update_require_signature\x00: true", "db_require_signature\u200b: true", "trusted_keys\x00:\n  release: abc",
		"trusted_keys: {release: abc}", "trusted_keys: [release, abc]", "trusted_keys: release",
		"trusted_keys:\n  release: {key: abc}", "trusted_keys:\n  release: [abc]",
		"trusted_keys:\n  release\x00: abc", "trusted_keys:\n  release:\n    key: abc",
	} {
		t.Run(strconv.Quote(body), func(t *testing.T) {
			t.Setenv("BONGSU_HOME", t.TempDir())
			path, _ := Path()
			if err := os.WriteFile(path, []byte(body+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := Load(); err == nil {
				t.Fatal("malformed security configuration accepted")
			}
		})
	}
}

func TestSaveLoadQuotedScalarProperty(t *testing.T) {
	values := []string{"publisher:prod", "name # hash", `Publisher "Prod"`, "한글 日本語 é 🔑", `path\key`, "line\nbreak\tvalue", "O'Brien", "{literal}", "[literal]", ""}
	for _, signer := range values {
		for _, key := range values[:5] {
			t.Run(strconv.Quote(signer)+"/"+strconv.Quote(key), func(t *testing.T) {
				t.Setenv("BONGSU_HOME", t.TempDir())
				cfg := Defaults()
				cfg.Signer = signer
				cfg.TrustedKeys[key] = signer
				if err := Save(cfg); err != nil {
					t.Fatal(err)
				}
				got, _, warnings, err := LoadWithWarnings()
				value, exists := got.TrustedKeys[key]
				if err != nil || len(warnings) != 0 || got.Signer != signer || !exists || value != signer || len(got.TrustedKeys) != 1 {
					t.Fatalf("cfg=%#v warnings=%v err=%v", got, warnings, err)
				}
			})
		}
	}
}

func TestLoadSingleQuotesAndDuplicateKeys(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	path, _ := Path()
	body := "signer: before\nsigner: 'Publisher ''Prod'' \\literal: # 한글'\ntrusted_keys:\n  'publisher:prod': old\n  \"publisher:prod\": 'path\\key'\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got, _, warnings, err := LoadWithWarnings()
	if err != nil || got.Signer != `Publisher 'Prod' \literal: # 한글` || got.TrustedKeys["publisher:prod"] != `path\key` {
		t.Fatalf("cfg=%#v err=%v", got, err)
	}
	if len(warnings) != 2 || !strings.Contains(warnings[0], "duplicate") || !strings.Contains(warnings[0], path+":2:") || !strings.Contains(warnings[1], "duplicate") || !strings.Contains(warnings[1], path+":5:") {
		t.Fatalf("warnings=%v", warnings)
	}
	if err := Save(got); err != nil {
		t.Fatal(err)
	}
	reloaded, _, warnings, err := LoadWithWarnings()
	if err != nil || len(warnings) != 0 || reloaded.Signer != got.Signer || reloaded.TrustedKeys["publisher:prod"] != got.TrustedKeys["publisher:prod"] {
		t.Fatalf("reloaded=%#v warnings=%v err=%v", reloaded, warnings, err)
	}
}

func TestSignatureMinVersionParsingAndSave(t *testing.T) {
	for _, value := range []string{"1", "2"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("BONGSU_HOME", t.TempDir())
			path, _ := Path()
			if err := os.WriteFile(path, []byte("signature_min_version: "+value+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, _, warnings, err := LoadWithWarnings()
			if err != nil || len(warnings) != 0 {
				t.Fatalf("warnings=%v err=%v", warnings, err)
			}
			if err := Save(cfg); err != nil {
				t.Fatal(err)
			}
			body, err := os.ReadFile(path)
			if err != nil || !strings.Contains(string(body), "signature_min_version: "+value+"\n") {
				t.Fatalf("saved=%s err=%v", body, err)
			}
		})
	}
	for _, value := range []string{"", "0", "-1", "3", "two", "2.0", "[2]", "{version: 2}"} {
		t.Run("invalid/"+value, func(t *testing.T) {
			t.Setenv("BONGSU_HOME", t.TempDir())
			path, _ := Path()
			if err := os.WriteFile(path, []byte("signature_min_version: "+value+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := Load(); err == nil || !strings.Contains(err.Error(), "signature_min_version") {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestCheckSignatureVersion(t *testing.T) {
	if Defaults().SignatureMinVersion != 1 {
		t.Fatal("signature minimum must default to 1")
	}
	for _, minimum := range []int{0, 1, 2, -1, 3} {
		for _, version := range []int{1, 2} {
			cfg := Defaults()
			cfg.SignatureMinVersion = minimum
			err := cfg.CheckSignatureVersion(version)
			wantError := minimum < 0 || minimum > 2 || version < minimum
			if (err != nil) != wantError {
				t.Errorf("minimum=%d version=%d err=%v", minimum, version, err)
			}
		}
	}
}

func TestLoadForCLIPrintsDuplicateAndUnknownWarnings(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	path, _ := Path()
	if err := os.WriteFile(path, []byte("unknown: [ignored]\noffline: false\noffline: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	stderr := os.Stderr
	os.Stderr = output
	defer func() { os.Stderr = stderr }()
	cfg, gotPath, err := LoadForCLI()
	if err != nil || !cfg.Offline || gotPath != path {
		t.Fatalf("cfg=%#v path=%q err=%v", cfg, gotPath, err)
	}
	body, err := os.ReadFile(output.Name())
	if err != nil || !strings.Contains(string(body), "unknown configuration key") || !strings.Contains(string(body), `duplicate configuration key "offline"; last value wins`) {
		t.Fatalf("warnings=%s err=%v", body, err)
	}
}

func TestDuplicateTrustedKeysBlockLastWins(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	path, _ := Path()
	if err := os.WriteFile(path, []byte("trusted_keys:\n  old: revoked\ntrusted_keys:\n  release: current\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, _, warnings, err := LoadWithWarnings()
	if err != nil || len(cfg.TrustedKeys) != 1 || cfg.TrustedKeys["release"] != "current" || len(warnings) != 1 || !strings.Contains(warnings[0], `duplicate configuration key "trusted_keys"`) {
		t.Fatalf("cfg=%#v warnings=%v err=%v", cfg, warnings, err)
	}
}
