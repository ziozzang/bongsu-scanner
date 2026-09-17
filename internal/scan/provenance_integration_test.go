package scan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestProvenanceDirectoryAndArchive(t *testing.T) {
	entries := []tarEntry{
		{name: "usr/local/bundle/gems/rbs-3.4.0/Gemfile.lock", data: []byte("GEM\n  specs:\n    unused (1.0.0)\n")},
		{name: "usr/local/lib/python3/site-packages/pkg/requirements.txt", data: []byte("unused==1.0.0\n")},
		{name: "app/node_modules/parent/package-lock.json", data: []byte(`{"packages":{"node_modules/nested":{"version":"1.0.0"}}}`)},
		{name: "app/node_modules/parent/node_modules/nested/package.json", data: []byte(`{"name":"nested","version":"1.0.0"}`)},
		{name: "app/requirements-dev.txt", data: []byte("app-dep==1.0.0\n")},
		{name: "opt/yarn-v1.22.22/package.json", data: []byte(`{"name":"yarn","version":"1.22.22"}`)},
	}
	check := func(t *testing.T, r Result) {
		t.Helper()
		if len(r.Packages) != 3 {
			t.Fatalf("packages=%+v", r.Packages)
		}
		want := map[string]string{"app-dep": "lockfile", "nested": "installed", "yarn": "package.json"}
		for _, p := range r.Packages {
			if want[p.Name] != p.Evidence {
				t.Fatalf("package=%+v", p)
			}
		}
	}
	t.Run("archive", func(t *testing.T) {
		r, err := Archive(writeTemp(t, "rootfs.tar", buildTar(t, entries)), Options{})
		if err != nil {
			t.Fatal(err)
		}
		check(t, r)
	})
	for _, workers := range []int{1, 4} {
		t.Run(string(rune('0'+workers)), func(t *testing.T) {
			root := t.TempDir()
			for _, e := range entries {
				p := filepath.Join(root, e.name)
				if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, e.data, 0644); err != nil {
					t.Fatal(err)
				}
			}
			r, err := DirectoryContext(context.Background(), root, "fixture", Options{Workers: workers, SkipBinaries: true})
			if err != nil {
				t.Fatal(err)
			}
			check(t, r)
		})
	}
}

// Opt in only with the review images already pulled into the local daemon.
func TestProvenanceDockerReview(t *testing.T) {
	if os.Getenv("BONGSU_TEST_PROVENANCE_DOCKER") != "1" {
		t.Skip("set BONGSU_TEST_PROVENANCE_DOCKER=1 to rescan the review images")
	}
	for _, tc := range []struct {
		image string
		want  int
	}{{"ruby:3.3-slim", 168}, {"node:22-slim", 275}} {
		t.Run(tc.image, func(t *testing.T) {
			r, err := Target(context.Background(), "docker://"+tc.image, Options{Progress: func(p Progress) {
				if p.Stage == "catalog" {
					t.Log(p.Message)
				}
			}})
			if err != nil {
				t.Fatal(err)
			}
			counts := map[string]int{}
			for _, p := range r.Packages {
				counts[p.Type]++
				if p.Name == "yarn" {
					t.Logf("yarn: %+v", p)
				}
			}
			t.Logf("image=%s packages=%d by-type=%v digest=%v scan=%+v", tc.image, len(r.Packages), counts, r.Image.RepoDigests, r.Scan)
			if len(r.Packages) != tc.want {
				t.Errorf("packages=%d review Trivy=%d", len(r.Packages), tc.want)
			}
		})
	}
}

func TestProvenanceInstalledMetadata(t *testing.T) {
	for _, tc := range []struct {
		path string
		data []byte
	}{
		{"var/lib/dpkg/status", []byte("Package: dep\nVersion: 1\nStatus: install ok installed\n")},
		{"lib/apk/db/installed", []byte("P:dep\nV:1\n")},
		{"lib/site-packages/dep-1.dist-info/METADATA", []byte("Name: dep\nVersion: 1\n")},
		{"lib/site-packages/dep.egg-info/PKG-INFO", []byte("Name: dep\nVersion: 1\n")},
		{"lib/site-packages/dep.egg-info", []byte("Name: dep\nVersion: 1\n")},
		{"lib/ruby/gems/3.3.0/specifications/dep-1.gemspec", []byte("s.name = 'dep'\ns.version = '1'\n")},
		{"var/lib/rpm/Packages.db", rpmTestNDB(rpmTestHeader(0))},
	} {
		t.Run(tc.path, func(t *testing.T) {
			got, _ := catalog([]File{{Path: tc.path, Data: tc.data}}, nil)
			if len(got) != 1 || got[0].Evidence != "installed" {
				t.Fatalf("packages=%+v", got)
			}
		})
	}
	// A parallel walk replays raw RPM parser results through addPackage.
	var c cataloger
	scanRPMDatabase(File{Path: "var/lib/rpm/Packages.db", Data: rpmTestNDB(rpmTestHeader(0))}, "", c.addPackage)
	got, _ := c.finish()
	if len(got) != 1 || got[0].Evidence != "installed" {
		t.Fatalf("replayed RPM packages=%+v", got)
	}
}

func TestProvenanceNestedDirectoryEvidence(t *testing.T) {
	lock := []byte(`{"packages":{"node_modules/dep":{"version":"1.0.0"}}}`)
	const dir = "app/node_modules/@scope/parent"
	root := t.TempDir()
	gapWrite(t, root, dir+"/package-lock.json", lock)
	if err := os.MkdirAll(filepath.Join(root, dir, "node_modules"), 0755); err != nil {
		t.Fatal(err)
	}
	for _, workers := range []int{1, 4} {
		r, err := DirectoryContext(context.Background(), root, "fixture", Options{Workers: workers, SkipBinaries: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Packages) != 1 || r.Packages[0].Evidence != "lockfile" {
			t.Errorf("workers=%d packages=%+v", workers, r.Packages)
		}
	}
	for _, removed := range []bool{false, true} {
		base := buildTar(t, []tarEntry{{name: dir + "/package-lock.json", data: lock}, {name: dir + "/node_modules/", typeflag: '5'}})
		layers := [][]byte{base}
		if removed {
			layers = append(layers, buildTar(t, []tarEntry{{name: dir + "/.wh.node_modules"}}))
		}
		r, err := Archive(writeTemp(t, "image.tar", dockerArchive(t, layers...)), Options{})
		if err != nil {
			t.Fatal(err)
		}
		want := 1
		if removed {
			want = 0
		}
		if len(r.Packages) != want {
			t.Errorf("removed=%v packages=%+v", removed, r.Packages)
		}
	}
}
