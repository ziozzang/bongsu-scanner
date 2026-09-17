package scan

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unsafe"
)

func TestReviewMergedSourceVersion(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		for _, lateOS := range []bool{false, true} {
			t.Run(fmt.Sprintf("reverse=%t/lateOS=%t", reverse, lateOS), func(t *testing.T) {
				files := []File{
					{Path: "var/lib/dpkg/status", Data: []byte("Package: libfoo\nVersion: 1\nSource: foo\n")},
					{Path: "var/lib/dpkg/status.d/foo", Data: []byte("Package: libfoo\nVersion: 1\nSource: foo (2)\n")},
				}
				if reverse {
					files[0], files[1] = files[1], files[0]
				}
				var c cataloger
				for _, f := range files {
					c.addFile(f)
				}
				ns := "debian"
				qualifiers := "upstream=foo%402"
				if lateOS {
					c.addFile(File{Path: "etc/os-release", Data: []byte("ID=ubuntu\n")})
					ns = "ubuntu"
					qualifiers = "distro=ubuntu&" + qualifiers
				}
				pkgs, _ := c.finish()
				wantPURLs(t, pkgs, "pkg:deb/"+ns+"/libfoo@1?"+qualifiers)
				if len(pkgs) != 1 || pkgs[0].SourceName != "foo" || pkgs[0].SourceVersion != "2" {
					t.Fatalf("source version lost: %+v", pkgs)
				}
			})
		}
	}
	// Also exercise a merge after both packages already have a PURL.
	for _, source := range []string{"foo", "other"} {
		prev := Package{Type: "deb", Name: "libfoo", Version: "1", SourceName: "foo"}
		prev.PURL = buildPURL(prev)
		p := prev
		p.SourceName, p.SourceVersion = source, "2"
		p.PURL = buildPURL(p)
		mergePackage(&prev, p)
		want := "pkg:deb/debian/libfoo@1?upstream=foo"
		if source == "foo" {
			want += "%402"
		} else if prev.SourceVersion != "" {
			t.Fatalf("version taken from a different source: %+v", prev)
		}
		if prev.PURL != want {
			t.Errorf("merged PURL = %q, want %q", prev.PURL, want)
		}
	}
}

func TestReviewTOMLBasicStringEscapes(t *testing.T) {
	for _, file := range []string{"poetry.lock", "uv.lock", "Cargo.lock"} {
		t.Run(file, func(t *testing.T) {
			_, pkgs, _ := run(t, map[string]string{file: "[[package]]\nname = \"r\\u0065quests\"\nversion = \"\\U00000032.32.3\"\n"})
			typ := "pypi"
			if file == "Cargo.lock" {
				typ = "cargo"
			}
			wantPURLs(t, pkgs, "pkg:"+typ+"/requests@2.32.3")
		})
	}
	for _, tc := range []struct{ value, want string }{
		{`"line\n\t\"quote\"\\\b\f\r\u0065\U0001F600"`, "line\n\t\"quote\"\\\b\f\re😀"},
		{`'line\n\t\"quote\"\\\u0065\U0001F600'`, `line\n\t\"quote\"\\\u0065\U0001F600`},
		{`'"quoted"'`, `"quoted"`},
		{`"'quoted'"`, `'quoted'`},
	} {
		entries := tomlPackages("[[package]]\nname = " + tc.value + " # comment\n")
		if len(entries) != 1 || entries[0]["name"] != tc.want {
			t.Errorf("value %s: got %v, want %q", tc.value, entries, tc.want)
		}
	}
}

func TestReviewDpkgInstalledStatus(t *testing.T) {
	for _, status := range []string{"hold ok installed", "install ok installed", "deinstall ok installed", "purge ok installed", "unknown ok installed", "hold\tok\tinstalled"} {
		t.Run(status, func(t *testing.T) {
			_, pkgs, _ := run(t, map[string]string{"var/lib/dpkg/status": "Package: curl\nVersion: 1\nStatus: " + status + "\n"})
			wantPURLs(t, pkgs, "pkg:deb/debian/curl@1")
		})
	}
	for _, status := range []string{"deinstall ok config-files", "hold reinstreq installed", "install ok installed-extra", "install ok installed extra", "installed"} {
		_, pkgs, _ := run(t, map[string]string{"var/lib/dpkg/status": "Package: curl\nVersion: 1\nStatus: " + status + "\n"})
		if len(pkgs) != 0 {
			t.Errorf("status %q included: %+v", status, pkgs)
		}
	}
}

func TestReviewYarnNestedVersion(t *testing.T) {
	for _, body := range []string{
		"foo@^1.0.0:\n  version \"1.2.3\"\n  dependencies:\n    version \"^9.0.0\"\n",
		"\"foo@npm:^1.0.0\":\n  version: 1.2.3\n  dependencies:\n    version: \"npm:^9.0.0\"\n",
	} {
		_, pkgs, _ := run(t, map[string]string{"yarn.lock": body})
		wantPURLs(t, pkgs, "pkg:npm/foo@1.2.3")
	}
}

func TestReviewYarnAliases(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{"\"alias@npm:lodash@^4.17.0\":\n  version \"4.17.21\"\n", "pkg:npm/lodash@4.17.21"},
		{"\"alias@npm:^4.17.0\":\n  version: 4.17.21\n  resolution: \"lodash@npm:4.17.21\"\n", "pkg:npm/lodash@4.17.21"},
		{"\"alias@npm:@scope/real@^1\":\n  version \"1.2.3\"\n", "pkg:npm/%40scope/real@1.2.3"},
		{"\"alias@npm:^1\":\n  version: 1.2.3\n  resolution: \"@scope/real@npm:1.2.3\"\n  dependencies:\n    resolution: \"wrong@npm:9\"\n", "pkg:npm/%40scope/real@1.2.3"},
	} {
		_, pkgs, _ := run(t, map[string]string{"yarn.lock": tc.body})
		wantPURLs(t, pkgs, tc.want)
	}
}

func TestReviewTOMLStrings(t *testing.T) {
	for _, file := range []string{"poetry.lock", "uv.lock", "Cargo.lock"} {
		for _, quote := range []string{`"""`, "'''"} {
			t.Run(file+quote, func(t *testing.T) {
				body := "[[package]] # real package\nname = \"requests\" # name comment\nversion = '2.32.3' # version comment\ndescription = " + quote + "\nname = \"wrong\"\nversion = \"9\"\n[[package]]\nname = \"fake\"\nversion = \"99\"\n" + quote + " # closing\n[[package]]\nname = 'next'\nversion = \"1#part\" # keep hash inside quotes\n"
				_, pkgs, _ := run(t, map[string]string{file: body})
				typ := "pypi"
				if file == "Cargo.lock" {
					typ = "cargo"
				}
				wantPURLs(t, pkgs, "pkg:"+typ+"/requests@2.32.3", "pkg:"+typ+"/next@1%23part")
			})
		}
	}
}

func TestReviewRequirementsOptionsAndParentheses(t *testing.T) {
	for _, option := range []string{"--hash sha256:" + strings.Repeat("a", 64), "--hash=sha256:" + strings.Repeat("b", 64), "--index-url https://example.com/simple", "--extra-index-url https://example.com/simple", "--find-links https://example.com/wheels", "-i https://example.com/simple", "-f ./wheels", "-c constraints.txt", "-r other.txt", "-e ./local"} {
		t.Run(option, func(t *testing.T) {
			_, pkgs, _ := run(t, map[string]string{"requirements.txt": "requests==2.32.3 " + option + "\n"})
			wantPURLs(t, pkgs, "pkg:pypi/requests@2.32.3")
		})
	}
	for _, spec := range []string{"requests(==2.32.3)", "requests (== 2.32.3)", "requests[security](==2.32.3)"} {
		_, pkgs, _ := run(t, map[string]string{"requirements.txt": spec})
		wantPURLs(t, pkgs, "pkg:pypi/requests@2.32.3")
	}
}

func TestReviewGoModNoStdlib(t *testing.T) {
	for _, directives := range []string{"go 1.21.5", "toolchain go1.22.4", "go 1.21.5\ntoolchain go1.22.4"} {
		pkgs, _ := catalog([]File{{Path: "go.mod", Data: []byte("module x\n" + directives + "\nrequire example.com/mod v1.2.3\n")}}, []Package{{Type: "golang", Name: "stdlib", Version: "1.25.0", Source: "bin/app"}})
		wantPURLs(t, pkgs, "pkg:golang/example.com/mod@v1.2.3", "pkg:golang/stdlib@1.25.0")
	}
}

func TestReviewGoModExcludes(t *testing.T) {
	_, pkgs, _ := run(t, map[string]string{"go.mod": `module x
exclude example.com/a v1.0.0
require (
 example.com/a v1.0.0
 example.com/a v1.1.0
 example.com/b v1.0.0
 example.com/c v1.0.0
)
replace example.com/b => example.com/fork v2.0.0
exclude (
 example.com/b v1.0.0
 example.com/c v0.9.0
)
`})
	wantPURLs(t, pkgs, "pkg:golang/example.com/a@v1.1.0", "pkg:golang/example.com/c@v1.0.0")
}

func TestReviewGoModQuotedEscapes(t *testing.T) {
	_, pkgs, _ := run(t, map[string]string{"go.mod": "module x\nrequire (\n \"example.com/\\x6dod\" \"v1.2.3\"\n `example.com/raw` `v1.0.0`\n \"example.com/\\x6fld\" v1.0.0\n \"example.com/\\x73kip\" v1.0.0\n)\nreplace \"example.com/\\x6fld\" => \"example.com/\\x6eew\" v1.1.0\nexclude \"example.com/\\x73kip\" v1.0.0\n"})
	wantPURLs(t, pkgs, "pkg:golang/example.com/mod@v1.2.3", "pkg:golang/example.com/raw@v1.0.0", "pkg:golang/example.com/new@v1.1.0")
}

func TestReviewParagraphLongLine(t *testing.T) {
	for _, size := range []int{(1 << 20) + 1, maxMetadata - 100} {
		long := strings.Repeat("x", size)
		for _, tc := range []struct{ file, body, prefix string }{
			{"var/lib/dpkg/status", "Package: first\nVersion: 1\nDescription: " + long + "\n\nPackage: last\nVersion: 2\n", "pkg:deb/debian/"},
			{"lib/apk/db/installed", "P:first\nV:1\nT:" + long + "\n\nP:last\nV:2\n", "pkg:apk/alpine/"},
		} {
			_, pkgs, _ := run(t, map[string]string{tc.file: tc.body})
			wantPURLs(t, pkgs, tc.prefix+"first@1", tc.prefix+"last@2")
		}
	}
}

func TestReviewMergedUpstreamPURL(t *testing.T) {
	for _, typ := range []string{"deb", "apk"} {
		for _, reverse := range []bool{false, true} {
			extra := []Package{{Type: typ, Name: "libfoo", Version: "1", Source: "first"}, {Type: typ, Name: "libfoo", Version: "1", SourceName: "foo", SourceVersion: "2", Source: "second"}}
			if reverse {
				extra[0], extra[1] = extra[1], extra[0]
			}
			pkgs, _ := catalog(nil, extra)
			ns := "debian"
			if typ == "apk" {
				ns = "alpine"
			}
			wantPURLs(t, pkgs, "pkg:"+typ+"/"+ns+"/libfoo@1?upstream=foo%402")
		}
	}
}

func TestReviewPURLColon(t *testing.T) {
	p := Package{Type: "deb", Name: "git", Version: "1:2.47.3-0+deb13u1", SourceName: "git-src", SourceVersion: "2:3"}
	if got, want := buildPURL(p), "pkg:deb/debian/git@1:2.47.3-0%2Bdeb13u1?upstream=git-src%402:3"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestReviewParagraphScanErrorCounts(t *testing.T) {
	before := paragraphScanErrors.Load()
	entries := paragraphs([]byte("Package: first\nVersion: 1\n\nPackage: second\nDescription: " + strings.Repeat("x", maxMetadata+1)))
	if len(entries) != 2 || entries[0]["Package"] != "first" || entries[1]["Package"] != "second" {
		t.Fatalf("parsed prefix lost: %+v", entries)
	}
	if got := paragraphScanErrors.Load(); got != before+1 {
		t.Fatalf("error count = %d, want %d", got, before+1)
	}
}

func TestReviewTOMLStringBoundaries(t *testing.T) {
	for _, description := range []string{
		`description = "escaped \" # still inside the string" # comment`,
		`description = "''' # not a multiline literal" # comment`,
		`description = '""" # not a multiline basic string' # comment`,
		`description = """inline # multiline string""" # comment`,
		`description = '''inline # multiline string''' # comment`,
		"description = \"\"\"\n\\\"\"\"\nname = \"wrong\"\n\"\"\"\"\" # closing with two literal quotes",
		"description = '''\nname = 'wrong'\n''''' # closing with two literal quotes",
	} {
		_, pkgs, _ := run(t, map[string]string{"poetry.lock": "[[package]]\nname = 'requests'\n" + description + "\nversion = '2.32.3' # comment\n"})
		wantPURLs(t, pkgs, "pkg:pypi/requests@2.32.3")
	}
	// A multiline string outside a package must not introduce fake packages.
	_, pkgs, _ := run(t, map[string]string{"Cargo.lock": "description = '''\n[[package]]\nname = 'fake'\nversion = '9'\n'''\n[[package]]\nname = 'real'\nversion = '1'\n"})
	wantPURLs(t, pkgs, "pkg:cargo/real@1")
}

func TestReviewCatalogerLateOSRelease(t *testing.T) {
	for _, typ := range []string{"deb", "apk"} {
		t.Run(typ, func(t *testing.T) {
			var c cataloger
			c.addPackages([]Package{{Type: typ, Name: "libfoo", Version: "1", Arch: "amd64", Source: "first"}})
			before, _ := c.finish()
			if before[0].Distro != "" {
				t.Fatalf("unexpected initial distro: %+v", before)
			}
			c.addFile(File{Path: "usr/lib/os-release", Data: []byte("ID=debian\nVERSION_ID=12\n")})
			c.addPackages([]Package{{Type: typ, Name: "libfoo", Version: "1", Arch: "amd64", Source: "second", SourceName: "foo", SourceVersion: "2"}})
			c.addFile(File{Path: "etc/os-release", Data: []byte("ID=ubuntu\nVERSION_ID=24.04\n")})
			// Neither nested copies nor a lower-priority root copy may win.
			c.addFile(File{Path: "nested/etc/os-release", Data: []byte("ID=wrong\n")})
			c.addFile(File{Path: "usr/lib/os-release", Data: []byte("ID=wrong\n")})
			c.addPackages([]Package{{Type: typ, Namespace: "ubuntu", Name: "libfoo", Version: "1", Arch: "amd64", Source: "third"}})
			pkgs, osr := c.finish()
			if osr == nil || osr.ID != "ubuntu" || len(pkgs) != 1 {
				t.Fatalf("late OS resolution: os=%+v packages=%+v", osr, pkgs)
			}
			p := pkgs[0]
			want := "pkg:" + typ + "/ubuntu/libfoo@1?arch=amd64&distro=ubuntu-24.04&upstream=foo%402"
			if p.Namespace != "ubuntu" || p.Distro != "ubuntu-24.04" || p.PURL != want || p.Source != "first;second;third" {
				t.Fatalf("late OS package: %+v, want %s", p, want)
			}
		})
	}
}

func TestReviewCatalogerParsesImmediately(t *testing.T) {
	var c cataloger
	f := File{Path: "go.mod", Data: []byte("module app\nrequire example.com/first v1.2.3\n")}
	c.addFile(f)
	if len(c.seen)+len(c.pending) != 1 {
		t.Fatalf("file parsing deferred: seen=%d pending=%d", len(c.seen), len(c.pending))
	}
	clear(f.Data)
	pkgs, _ := c.finish()
	wantPURLs(t, pkgs, "pkg:golang/example.com/first@v1.2.3")
}

func TestReviewCatalogerExplicitOSIdentity(t *testing.T) {
	var c cataloger
	c.addPackages([]Package{
		{Type: "deb", Name: "libfoo", Version: "1", Source: "default"},
		{Type: "deb", Name: "libfoo", Version: "1", Namespace: "debian", Distro: "debian-12", PURL: "custom", Source: "explicit"},
	})
	c.addFile(File{Path: "etc/os-release", Data: []byte("ID=ubuntu\nVERSION_ID=24.04\n")})
	pkgs, _ := c.finish()
	if len(pkgs) != 2 {
		t.Fatalf("explicit namespace merged with unresolved default: %+v", pkgs)
	}
	if pkgs[0].Namespace != "debian" || pkgs[0].Distro != "debian-12" || pkgs[0].PURL != "custom" {
		t.Fatalf("explicit identity changed: %+v", pkgs[0])
	}
	if pkgs[1].Namespace != "ubuntu" || pkgs[1].Distro != "ubuntu-24.04" {
		t.Fatalf("default identity unresolved: %+v", pkgs[1])
	}
}

// Parser substrings must not keep the complete metadata string alive.
// Compare backing pointers without mutating strings or relying on GC timing.
func TestReviewCatalogDoesNotRetainInputStrings(t *testing.T) {
	metadata := strings.Repeat("x", 1<<20)
	p := Package{}
	fields := reflect.ValueOf(&p).Elem()
	for i := 0; i < fields.NumField(); i++ {
		if fields.Field(i).Kind() == reflect.String {
			fields.Field(i).SetString(metadata[:8])
		}
	}
	p.Type = "maven"
	pkgs, _ := catalog(nil, []Package{p})
	if len(pkgs) != 1 {
		t.Fatalf("packages=%d", len(pkgs))
	}
	got := reflect.ValueOf(pkgs[0])
	for i := 0; i < fields.NumField(); i++ {
		if fields.Field(i).Kind() != reflect.String || fields.Type().Field(i).Name == "Type" {
			continue
		}
		before, after := fields.Field(i).String(), got.Field(i).String()
		if before != after {
			t.Errorf("%s changed: %q -> %q", fields.Type().Field(i).Name, before, after)
		}
		if unsafe.StringData(before) == unsafe.StringData(after) {
			t.Errorf("%s still retains the full metadata string", fields.Type().Field(i).Name)
		}
	}
}
