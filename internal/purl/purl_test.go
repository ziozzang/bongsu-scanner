package purl

import (
	"reflect"
	"testing"
)

func TestParseRoundTrip(t *testing.T) {
	tests := []struct{ input, typ, ns, name, version, canonical string }{
		{"pkg:npm/%40scope/name@1.0", "npm", "@scope", "name", "1.0", "pkg:npm/%40scope/name@1.0"},
		{"pkg:npm/@scope%2Fname@1.0", "npm", "@scope", "name", "1.0", "pkg:npm/%40scope/name@1.0"},
		{"pkg:npm/@scope%2Fname", "npm", "@scope", "name", "", "pkg:npm/%40scope/name"},
		{"pkg:golang/github.com/foo/bar@v1.2.3", "golang", "github.com/foo", "bar", "v1.2.3", "pkg:golang/github.com/foo/bar@v1.2.3"},
		{"pkg:golang/github.com%2Ffoo%2Fbar@v1.2.3", "golang", "github.com/foo", "bar", "v1.2.3", "pkg:golang/github.com/foo/bar@v1.2.3"},
		{"pkg:golang/stdlib@1.24.0", "golang", "", "stdlib", "1.24.0", "pkg:golang/stdlib@1.24.0"},
		{"pkg:deb/debian/curl@1%3A2.0%2Bdeb13u1", "deb", "debian", "curl", "1:2.0+deb13u1", "pkg:deb/debian/curl@1:2.0%2Bdeb13u1"},
		{"pkg:deb/DEBIAN/CURL@1:2.0+deb13u1", "deb", "debian", "curl", "1:2.0+deb13u1", "pkg:deb/debian/curl@1:2.0%2Bdeb13u1"},
		{"pkg:apk/Alpine/MUSL@1.2.3-r0", "apk", "alpine", "musl", "1.2.3-r0", "pkg:apk/alpine/musl@1.2.3-r0"},
		{"pkg:pypi/Py_YAML..Foo@6.0", "pypi", "", "py-yaml-foo", "6.0", "pkg:pypi/py-yaml-foo@6.0"},
		{"pkg:pypi/vendor/PyYAML@6.0", "pypi", "", "pyyaml", "6.0", "pkg:pypi/pyyaml@6.0"},
		{"pkg:maven/org.Apache/Artifact@1.0", "maven", "org.Apache", "Artifact", "1.0", "pkg:maven/org.Apache/Artifact@1.0"},
		{"pkg:npm/LODASH@4.17.21", "npm", "", "lodash", "4.17.21", "pkg:npm/lodash@4.17.21"},
		{"PKG:NPM/lodash@4.0", "npm", "", "lodash", "4.0", "pkg:npm/lodash@4.0"},
		{"pkg:///npm/lodash@4.0", "npm", "", "lodash", "4.0", "pkg:npm/lodash@4.0"},
		{"pkg:cargo/serde@1.0", "cargo", "", "serde", "1.0", "pkg:cargo/serde@1.0"},
		{"pkg:gem/rack@2.0", "gem", "", "rack", "2.0", "pkg:gem/rack@2.0"},
		{"pkg:nuget/Newtonsoft.Json@13.0", "nuget", "", "Newtonsoft.Json", "13.0", "pkg:nuget/Newtonsoft.Json@13.0"},
		{"pkg:composer/Vendor/Package@1.0", "composer", "vendor", "package", "1.0", "pkg:composer/vendor/package@1.0"},
		{"pkg:github/OpenAI/Repo@main", "github", "openai", "repo", "main", "pkg:github/openai/repo@main"},
		{"pkg:generic/a%20b@v%3F1", "generic", "", "a b", "v?1", "pkg:generic/a%20b@v%3F1"},
		{"pkg:generic/bad%ZZ@1", "generic", "", "bad%ZZ", "1", "pkg:generic/bad%25ZZ@1"},
		{"pkg:npm/foo@1?Distro=abc%2Bdef&arch=amd64&empty=", "npm", "", "foo", "1", "pkg:npm/foo@1?arch=amd64&distro=abc%2Bdef"},
		{"pkg:npm/foo@1#src/./../lib", "npm", "", "foo", "1", "pkg:npm/foo@1#src/lib"},
		{"pkg:npm/foo@1#src/%2E/%2E%2E/lib", "npm", "", "foo", "1", "pkg:npm/foo@1#src/lib"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			p, e := Parse(tt.input)
			if e != nil {
				t.Fatal(e)
			}
			if p.Type != tt.typ || p.Namespace != tt.ns || p.Name != tt.name || p.Version != tt.version {
				t.Fatalf("components %+v", p)
			}
			if got := p.String(); got != tt.canonical {
				t.Fatalf("canonical %s want %s", got, tt.canonical)
			}
			again, e := Parse(p.String())
			if e != nil || !reflect.DeepEqual(p, again) {
				t.Fatalf("roundtrip %+v %+v %v", p, again, e)
			}
		})
	}
}
func TestFullName(t *testing.T) {
	for in, want := range map[string]string{"pkg:npm/%40scope/name@1": "@scope/name", "pkg:golang/example.com/org/mod@v1": "example.com/org/mod", "pkg:maven/org.apache/commons@1": "org.apache:commons", "pkg:deb/debian/curl@1": "curl", "pkg:apk/alpine/musl@1": "musl"} {
		p, e := Parse(in)
		if e != nil || p.FullName() != want {
			t.Fatalf("%s = %s %v", in, p.FullName(), e)
		}
	}
}
func TestRejectMissingIdentity(t *testing.T) {
	for _, in := range []string{"", "npm/foo", "pkg:", "pkg:npm", "pkg:npm/", "pkg:/foo"} {
		if _, e := Parse(in); e == nil {
			t.Fatalf("accepted %q", in)
		}
	}
}

func TestStringNormalizesConstructedPURL(t *testing.T) {
	p := PURL{Type: "NPM", Namespace: "@SCOPE", Name: "PKG", Version: "1", Qualifiers: map[string]string{"Z": "last", "a": "first", "empty": "", "": "ignored"}}
	if got := p.String(); got != "pkg:npm/%40scope/pkg@1?a=first&z=last" {
		t.Fatalf("canonical constructed purl %s", got)
	}
	if p.Type != "NPM" || p.Qualifiers["Z"] != "last" {
		t.Fatal("String mutated caller")
	}
}
