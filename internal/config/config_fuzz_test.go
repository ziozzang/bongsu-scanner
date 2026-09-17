package config

import (
	"reflect"
	"strings"
	"testing"
)

func FuzzParseConfig(f *testing.F) {
	for _, s := range []string{
		"# bongsu scanner configuration\nsigner: \"Jane <jane@example.com>\"\nprivate_key: \"signing.key\"\npublic_key: \"signing.pub\"\nhash: \"sha256\"\nformats: [spdx, cyclonedx]\nconcurrency: 4\noffline: true\ndb_require_signature: yes\nupdate_require_signature: off\nsignature_min_version: 2\ntrusted_keys:\n  release: \"path/to/publisher.pub\"\n  'it''s': 'a: value # not comment'\n",
		"\ufeffsigner: x\r\nformats: []\r\n",
		"signer: O'Brien # comment\nkey_path: ~/.bongsu/key\nunknown:\n  nested: [1, 2]\n  deeper:\n    - a\nconcurrency: -3\n",
		"trusted_keys: {a: b}\n",
		"trusted_keys:\n  a: b\n   c: d\n",
		"trusted_keys:\n  a: [1]\n",
		"  indented first\n",
		"signature_min_version: 3\n",
		"offline: maybe\n",
		"\"quoted:key\": \"v\\n\"\n'unterminated: x\n",
		"formats: [ 'a]', \"b #c\", ' d ', ]\n",
		"signer: \"\\xff\"\n",
		"\xff\xfe: bad\n",
		"a:\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		cfg, warnings, err := parse("scaner.yaml", data)
		if cfg.Concurrency < 1 && err == nil {
			t.Fatalf("parse accepted concurrency %d", cfg.Concurrency)
		}
		if err == nil && cfg.SignatureMinVersion != 1 && cfg.SignatureMinVersion != 2 {
			t.Fatalf("parse accepted signature_min_version %d", cfg.SignatureMinVersion)
		}
		for _, w := range warnings {
			if !strings.HasPrefix(w, "scaner.yaml:") {
				t.Fatalf("warning without location: %q", w)
			}
		}
		for k := range cfg.TrustedKeys {
			if !printableKey(k) {
				t.Fatalf("non-printable trusted key %q accepted", k)
			}
		}
		if err != nil {
			return
		}
		// What Save writes must read back to the same configuration.
		again, warnings, err := parse("scaner.yaml", render(cfg))
		if err != nil {
			t.Fatalf("rendered configuration does not parse: %v\n%s", err, render(cfg))
		}
		if len(warnings) > 0 {
			t.Fatalf("rendered configuration warns: %v\n%s", warnings, render(cfg))
		}
		if cfg.Formats == nil {
			cfg.Formats = nil
		}
		if !reflect.DeepEqual(cfg, again) {
			t.Fatalf("round trip mismatch:\n got %+v\nwant %+v\n%s", again, cfg, render(cfg))
		}
	})
}

func FuzzConfigScalars(f *testing.F) {
	f.Add(`"a\tb"`)
	f.Add(`'it''s'`)
	f.Add(`plain # comment`)
	f.Add(`[a, "b,c", 'd']`)
	f.Add(`{a: b}`)
	f.Add(`"unterminated`)
	f.Add(`'`)
	f.Fuzz(func(t *testing.T, s string) {
		if v, err := unquote(s); err == nil && strings.HasPrefix(s, "'") && strings.Contains(v, "''") && !strings.Contains(s, "''''") {
			t.Fatalf("unquote(%q) = %q kept doubled quotes", s, v)
		}
		_, _ = scalar(s)
		_, _ = parseList(s)
		_, _ = parseBool(s)
		if i := keySeparator(s); i >= len(s) || (i >= 0 && s[i] != ':') {
			t.Fatalf("keySeparator(%q) = %d", s, i)
		}
		if c := stripComment(s); len(c) > len(s) || !strings.HasPrefix(s, c) {
			t.Fatalf("stripComment(%q) = %q", s, c)
		}
		_ = printableKey(s)
	})
}
