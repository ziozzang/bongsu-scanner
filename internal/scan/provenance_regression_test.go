package scan

import (
	"strings"
	"testing"
)

func TestProvenanceDeclarations(t *testing.T) {
	for _, tc := range []struct{ path, data string }{
		{"Gemfile.lock", "GEM\n  specs:\n    rake (13.0.6)\n"},
		{"requirements.txt", "requests==2.31.0\n"},
		{"requirements-dev.txt", "requests==2.31.0\n"},
		{"poetry.lock", "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n"},
		{"uv.lock", "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n"},
		{"Pipfile.lock", `{"default":{"requests":{"version":"==2.31.0"}}}`},
		{"package-lock.json", `{"lockfileVersion":3,"packages":{"node_modules/dep":{"version":"1.0.0"}}}`},
		{"npm-shrinkwrap.json", `{"dependencies":{"dep":{"version":"1.0.0"}}}`},
		{"node_modules/.package-lock.json", `{"packages":{"node_modules/dep":{"version":"1.0.0"}}}`},
		{"yarn.lock", "dep@^1.0.0:\n  version \"1.0.0\"\n"},
		{"pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages:\n  dep@1.0.0:\n    resolution: {}\n"},
		{"go.mod", "module example.org/app\nrequire example.org/dep v1.0.0\n"},
		{"Cargo.lock", "[[package]]\nname = \"dep\"\nversion = \"1.0.0\"\n"},
		{"composer.lock", `{"packages":[{"name":"org/dep","version":"1.0.0"}]}`},
		{"packages.lock.json", `{"dependencies":{"net8.0":{"dep":{"resolved":"1.0.0"}}}}`},
	} {
		t.Run(tc.path, func(t *testing.T) {
			got, _ := catalog([]File{{Path: "app/" + tc.path, Data: []byte(tc.data)}}, nil)
			if len(got) != 1 || got[0].Evidence != "lockfile" {
				t.Fatalf("packages = %+v", got)
			}
		})
	}
}

func TestProvenanceInternalLocks(t *testing.T) {
	for _, dir := range []string{"usr/lib/ruby/gems/3.3.0/gems/rbs-3.4.0", "vendor/bundle/ruby/3.3.0", "usr/lib/python3/site-packages/pkg", "usr/lib/python3/dist-packages/pkg", "app/node_modules/pkg", "app/node_modules/@scope/pkg"} {
		t.Run(dir, func(t *testing.T) {
			got, _ := catalog([]File{{Path: dir + "/requirements.txt", Data: []byte("requests==2.31.0\n")}}, nil)
			if len(got) != 0 {
				t.Fatalf("internal declaration retained: %+v", got)
			}
		})
	}
}

func TestProvenanceNestedNPM(t *testing.T) {
	lock := File{Path: "app/node_modules/@scope/parent/package-lock.json", Data: []byte(`{"packages":{"node_modules/dep":{"version":"1.0.0"}}}`)}
	child := File{Path: "app/node_modules/@scope/parent/node_modules/dep/package.json", Data: []byte(`{"name":"dep","version":"1.0.0"}`)}
	for _, files := range [][]File{{lock, child}, {child, lock}} {
		got, _ := catalog(files, nil)
		if len(got) != 1 || got[0].Evidence != "installed" {
			t.Fatalf("packages = %+v", got)
		}
	}
}

func TestProvenanceInstalledWins(t *testing.T) {
	lock := File{Path: "app/requirements.txt", Data: []byte("my_pkg==1.0\n")}
	installed := File{Path: "lib/site-packages/my_pkg-2.0.dist-info/METADATA", Data: []byte("Name: my-pkg\nVersion: 2.0\n")}
	for _, files := range [][]File{{lock, installed}, {installed, lock}} {
		got, _ := catalog(files, nil)
		if len(got) != 1 || got[0].Version != "2.0" || got[0].Evidence != "installed" {
			t.Fatalf("packages = %+v", got)
		}
	}
}

func TestProvenanceApplicationBundles(t *testing.T) {
	for _, tc := range []struct {
		path, data string
		count      int
		evidence   string
	}{
		{"opt/yarn-v1.22.22/package.json", `{"name":"yarn","version":"1.22.22"}`, 1, "package.json"},
		{"home/tools/package.json", `{"name":"cli","version":"1.0.0","bin":"cli.js"}`, 1, "package.json"},
		{"usr/lib/tool/package.json", `{"name":"tool","version":"1.0.0"}`, 1, "package.json"},
		{"usr/local/lib/tool/package.json", `{"name":"tool","version":"1.0.0"}`, 1, "package.json"},
		{"usr/share/tool/package.json", `{"name":"tool","version":"1.0.0"}`, 1, "package.json"},
		{"srv/tool/package.json", `{"name":"tool","version":"1.0.0"}`, 1, "package.json"},
		{"app/package.json", `{"name":"workspace","version":"1.0.0","private":true,"bin":"cli.js"}`, 0, ""},
		{"optional/package.json", `{"name":"src","version":"1.0.0"}`, 0, ""},
		{"app/node_modules/pkg/package.json", `{"name":"pkg","version":"1.0.0","private":true}`, 1, "installed"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			got, _ := catalog([]File{{Path: tc.path, Data: []byte(tc.data)}}, nil)
			if len(got) != tc.count || (tc.count > 0 && got[0].Evidence != tc.evidence) {
				t.Fatalf("packages = %+v", got)
			}
		})
	}
}

func TestProvenanceManifestVersion(t *testing.T) {
	for _, tc := range []struct{ version, want string }{
		{"3.33.0.v20230218-1114", "3.33.0"},
		{"3.33.0.v20230218", "3.33.0"},
		{"1.0.0-SNAPSHOT-20230218-1114", "1.0.0-SNAPSHOT"},
		{"1.0.0-SNAPSHOT-20230218.111400-1", "1.0.0-SNAPSHOT"},
		{"4.3.0.RELEASE", "4.3.0.RELEASE"},
		{"1.0.0.v123", "1.0.0.v123"},
		{"1.0.0-20230218.111400-1", "1.0.0-20230218.111400-1"},
	} {
		t.Run(tc.version, func(t *testing.T) {
			data := gapZIP(t, map[string][]byte{"META-INF/MANIFEST.MF": []byte("Bundle-SymbolicName: org.eclipse.jdt.ecj\nBundle-Version: " + tc.version + "\n")})
			got, _ := catalog([]File{{Path: "ecj-4.27.jar", Data: data}}, nil)
			if len(got) != 1 || got[0].Version != tc.want || !strings.HasSuffix(got[0].PURL, "@"+tc.want) || got[0].Evidence != "installed" {
				t.Fatalf("packages = %+v", got)
			}
			original := ""
			if tc.want != tc.version {
				original = tc.version
			}
			if actual := packageJSONField(t, got[0], "version_original"); actual != original {
				t.Fatalf("original = %q, want %q", actual, original)
			}
		})
	}
}

func TestProvenanceDeclaredOptions(t *testing.T) {
	lock := File{Path: "usr/local/bundle/gems/rbs-3.4.0/Gemfile.lock", Data: []byte("GEM\n  specs:\n    rake (13.0.6)\n    rexml (3.2.6)\n")}
	for _, include := range []bool{false, true} {
		var messages []string
		c := cataloger{includeDeclared: include, opts: Options{Progress: func(p Progress) { messages = append(messages, p.Message) }}}
		c.addFile(lock)
		got, _ := c.finish()
		if include {
			if len(got) != 2 || c.declaredSkipped != 0 {
				t.Fatalf("packages=%+v skipped=%d", got, c.declaredSkipped)
			}
			for _, p := range got {
				if p.Evidence != "declared" {
					t.Fatalf("package = %+v", p)
				}
			}
		} else if len(got) != 0 || c.declaredSkipped != 2 || len(messages) != 1 || !strings.Contains(messages[0], "skipped 2 declared") {
			t.Fatalf("packages=%+v skipped=%d messages=%v", got, c.declaredSkipped, messages)
		}
	}
}

func TestProvenanceCustomPrefixes(t *testing.T) {
	for _, tc := range []struct {
		prefixes []string
		path     string
		want     int
	}{
		{[]string{"/tools"}, "tools/cli/package.json", 1},
		{[]string{"/tools"}, "toolset/cli/package.json", 0},
		{[]string{"/tools"}, "opt/cli/package.json", 0},
		{[]string{}, "opt/cli/package.json", 0},
	} {
		c := cataloger{npmBundlePrefixes: tc.prefixes}
		c.addFile(File{Path: tc.path, Data: []byte(`{"name":"cli","version":"1.0.0"}`)})
		got, _ := c.finish()
		if len(got) != tc.want {
			t.Fatalf("prefixes=%v path=%s packages=%+v", tc.prefixes, tc.path, got)
		}
	}
}

func TestProvenanceDedupeNamespacesAndLogging(t *testing.T) {
	for _, verbose := range []bool{false, true} {
		var messages []string
		c := cataloger{opts: Options{Verbose: verbose, Progress: func(p Progress) { messages = append(messages, p.Message) }}}
		for _, p := range []Package{
			{Type: "npm", Namespace: "@a", Name: "dep", Version: "1", Evidence: "lockfile"},
			{Type: "npm", Namespace: "@b", Name: "dep", Version: "2", Evidence: "installed"},
			{Type: "npm", Namespace: "@a", Name: "dep", Version: "3", Evidence: "installed"},
			{Type: "npm", Namespace: "@a", Name: "dep", Version: "4", Evidence: "installed"},
			{Type: "npm", Namespace: "@c", Name: "dep", Version: "1", Evidence: "lockfile"},
		} {
			c.addPackage(p)
		}
		got, _ := c.finish()
		if len(got) != 4 || (len(messages) > 0) != verbose {
			t.Fatalf("packages=%+v messages=%v", got, messages)
		}
	}
}

func TestProvenanceVersionOriginalMergeAndPOM(t *testing.T) {
	manifest := File{Path: "ecj.jar", Data: gapZIP(t, map[string][]byte{"META-INF/MANIFEST.MF": []byte("Bundle-SymbolicName: org.eclipse.jdt.ecj\nBundle-Version: 3.33.0.v20230218-1114\n")})}
	pom := File{Path: "ecj-copy.jar", Data: gapZIP(t, map[string][]byte{"META-INF/maven/org.eclipse.jdt/ecj/pom.properties": []byte("groupId=org.eclipse.jdt\nartifactId=ecj\nversion=3.33.0\n")})}
	for _, files := range [][]File{{manifest, pom}, {pom, manifest}} {
		got, _ := catalog(files, nil)
		if len(got) != 1 || got[0].VersionOriginal != "3.33.0.v20230218-1114" {
			t.Fatalf("packages=%+v", got)
		}
	}
	pom.Data = gapZIP(t, map[string][]byte{"META-INF/maven/org.eclipse.jdt/ecj/pom.properties": []byte("groupId=org.eclipse.jdt\nartifactId=ecj\nversion=3.33.0.v20230218-1114\n")})
	got, _ := catalog([]File{pom}, nil)
	if len(got) != 1 || got[0].Version != "3.33.0.v20230218-1114" || got[0].VersionOriginal != "" {
		t.Fatalf("POM changed: %+v", got)
	}
}
