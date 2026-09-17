package purl

import (
	"reflect"
	"strings"
	"testing"
)

func FuzzParseRoundTrip(f *testing.F) {
	for _, s := range []string{
		"pkg:deb/debian/curl@8.14.1-2%2Bdeb13u3?arch=amd64&distro=debian-13",
		"pkg:deb/ubuntu/libc6@2.35-0ubuntu3.8?arch=amd64&distro=ubuntu-22.04&upstream=glibc%402.35-0ubuntu3.9",
		"pkg:apk/alpine/musl@1.2.5-r0?arch=x86_64&distro=alpine-3.20.3",
		"pkg:rpm/fedora/LibX@1:2-3?epoch=1&upstream=Source%404-5",
		"pkg:npm/%400no-co/graphql.web@1.0.11",
		"pkg:npm/@scope%2Fname@1.0.0",
		"pkg:npm/lodash@4.17.21",
		"pkg:golang/github.com/creack/pty@v1.1.9",
		"pkg:golang/github.com%2Fcreack%2Fpty@v1.1.9",
		"pkg:golang/stdlib@1.22.4",
		"pkg:pypi/Zope.Interface_Foo@1",
		"pkg:maven/org.apache.commons/commons-lang3@3.12.0?type=jar&classifier=sources",
		"pkg:generic/a%20b%23c%3Fd@1%202#sub/path/../x/./y",
		"PKG:///Docker/Cassandra@sha256:244fd47e07d1004f0aed9c",
		"pkg:cargo/serde@1.0.197", "pkg:gem/rails@7.0.4", "pkg:nuget/Newtonsoft.Json@13.0.1",
		"pkg:composer/Laravel/Framework@v10.0.0", "pkg:oci/Debian@sha256:abc?repository_url=docker.io/library/debian",
		"pkg:type/name@", "pkg:type/@", "pkg:/", "pkg:", "pkg:a/b?=&k=&=v&K=V&k=v2#", "pkg:a/%2F/n", "pkg:a/n#%2F", "pkg:a/n#a%2F..",
		"pkg:a/n?k=%20", "pkg:golang/%2F", "pkg:npm/@", "pkg:type/name%00@%00", "pkg:t/n@v%zz",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p, err := Parse(s)
		if err != nil {
			if p.String() != "" && p.Name != "" && p.Type != "" {
				// An error must not leave a usable identity behind.
				t.Fatalf("Parse(%q) failed with %v but rendered %q", s, err, p.String())
			}
			return
		}
		if p.Type == "" || p.Name == "" {
			t.Fatalf("Parse(%q) succeeded without type/name: %+v", s, p)
		}
		if p.Type != strings.ToLower(p.Type) {
			t.Fatalf("Parse(%q) type %q not lowercased", s, p.Type)
		}
		for k, v := range p.Qualifiers {
			if k == "" || k != strings.ToLower(k) || v == "" {
				t.Fatalf("Parse(%q) qualifier %q=%q not normalized", s, k, v)
			}
		}
		rendered := p.String()
		if rendered == "" {
			t.Fatalf("Parse(%q) = %+v renders empty", s, p)
		}
		again, err := Parse(rendered)
		if err != nil {
			t.Fatalf("Parse(String(Parse(%q)) = %q) failed: %v", s, rendered, err)
		}
		if !reflect.DeepEqual(p, again) {
			t.Fatalf("round trip mismatch for %q:\n first: %+v (%q)\nsecond: %+v (%q)", s, p, rendered, again, again.String())
		}
		if again.String() != rendered {
			t.Fatalf("String not stable for %q: %q then %q", s, rendered, again.String())
		}
		_ = p.FullName()
	})
}

func FuzzEncode(f *testing.F) {
	f.Add("a b#c?d@e/f+g:h~i%")
	f.Add("")
	f.Add("\x00\xff")
	f.Fuzz(func(t *testing.T, s string) {
		e := Encode(s)
		if s == "" {
			if e != "" {
				t.Fatalf("Encode(\"\") = %q", e)
			}
			return
		}
		if d, err := Parse("pkg:t/" + e); err != nil || d.Name != s {
			t.Fatalf("Encode(%q) = %q does not decode: %+v %v", s, e, d, err)
		}
		if !strings.Contains(s, "/") {
			if EncodeSegments(s) != e && s != "" {
				t.Fatalf("EncodeSegments(%q) = %q != Encode %q", s, EncodeSegments(s), e)
			}
		}
		_ = pep503(s)
	})
}
