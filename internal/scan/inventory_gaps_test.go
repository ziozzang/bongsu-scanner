package scan

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

func gapZIP(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for name, data := range entries {
		w, err := z.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func gapWrite(t *testing.T, root, name string, data []byte) {
	t.Helper()
	p := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0644); err != nil {
		t.Fatal(err)
	}
}
func gapPURLs(pkgs []Package) map[string]Package {
	out := map[string]Package{}
	for _, p := range pkgs {
		out[p.PURL] = p
	}
	return out
}
func TestInventoryJavaArchives(t *testing.T) {
	inner := gapZIP(t, map[string][]byte{"META-INF/maven/org.example/lib/pom.properties": []byte("groupId=org.example\nartifactId=lib\nversion=1.2.3\n")})
	manifest := gapZIP(t, map[string][]byte{"META-INF/MANIFEST.MF": []byte("Manifest-Version: 1.0\r\nImplementation-Title: example\r\nImplementation-Version: 2.0\r\n\r\n")})
	for _, ext := range []string{"jar", "war", "ear", "jpi", "hpi"} {
		t.Run(ext, func(t *testing.T) {
			root := t.TempDir()
			gapWrite(t, root, "app."+ext, gapZIP(t, map[string][]byte{"WEB-INF/lib/lib.jar": inner}))
			gapWrite(t, root, "example.jar", manifest)
			gapWrite(t, root, "fallback-name-3.2-RC1.jar", gapZIP(t, map[string][]byte{"hello": []byte("world")}))
			r, err := Directory(root, "test", Options{SkipBinaries: true})
			if err != nil {
				t.Fatal(err)
			}
			found := gapPURLs(r.Packages)
			for _, want := range []string{"pkg:maven/org.example/lib@1.2.3", "pkg:generic/example@2.0", "pkg:generic/fallback-name@3.2-RC1"} {
				if _, ok := found[want]; !ok {
					t.Errorf("missing %s: %+v", want, r.Packages)
				}
			}
			if p := found["pkg:maven/org.example/lib@1.2.3"]; p.Source != "app."+ext+"!WEB-INF/lib/lib.jar" {
				t.Errorf("nested source = %q", p.Source)
			}
		})
	}
}
func TestInventoryInstalledNPM(t *testing.T) {
	root := t.TempDir()
	for name, data := range map[string]string{
		"usr/local/lib/node_modules/@scope/tool/package.json": `{"name":"@scope/tool","version":"1.2.3"}`,
		"app/node_modules/plain/package.json":                 `{"name":"plain","version":"2.0.0"}`,
		"app/node_modules/link/package.json":                  `{"name":"link","version":"1.0.0","link":true}`,
		"app/node_modules/workspace/package.json":             `{"name":"workspace","private":true}`,
		"app/package.json":                                    `{"name":"root","version":"9.0.0","private":true}`,
		"app/node_modules/plain/Package.json":                 `{"name":"wrongcase","version":"9.0.0"}`,
		"app/package-lock.json":                               `{"lockfileVersion":3,"packages":{"node_modules/plain":{"version":"2.0.0"}}}`,
	} {
		gapWrite(t, root, name, []byte(data))
	}
	r, err := Directory(root, "test", Options{SkipBinaries: true})
	if err != nil {
		t.Fatal(err)
	}
	found := gapPURLs(r.Packages)
	if len(found) != 2 || found["pkg:npm/%40scope/tool@1.2.3"].Name != "tool" || found["pkg:npm/plain@2.0.0"].Name != "plain" {
		t.Fatalf("packages = %+v", r.Packages)
	}
}
func TestInventoryInstalledGems(t *testing.T) {
	root := t.TempDir()
	gapWrite(t, root, "ruby/gems/3.3.0/specifications/my-gem-1.2.3.gemspec", []byte("Gem::Specification.new do |s|\n s.name = 'my-gem'.freeze\n s.version = '1.2.3'\nend\n"))
	gapWrite(t, root, "ruby/gems/3.3.0/specifications/default/rake-13.2.1.gemspec", []byte("Gem::Specification.new do |spec|\n spec.name = \"rake\"\n spec.version = Gem::Version.new(\"13.2.1\")\nend\n"))
	gapWrite(t, root, "ruby/gems/3.3.0/specifications/filename-gem-2.4.gemspec", []byte("# unavailable generated metadata\n"))
	r, err := Directory(root, "test", Options{SkipBinaries: true})
	if err != nil {
		t.Fatal(err)
	}
	found := gapPURLs(r.Packages)
	for _, want := range []string{"pkg:gem/my-gem@1.2.3", "pkg:gem/rake@13.2.1", "pkg:gem/filename-gem@2.4"} {
		if _, ok := found[want]; !ok {
			t.Errorf("missing %s: %+v", want, r.Packages)
		}
	}
}

func TestInventoryJavaMetadataPrecedence(t *testing.T) {
	for _, tc := range []struct{ name, manifest, want string }{
		{"bundle.jar", "Bundle-SymbolicName: org.example.\r\n bundle;singleton:=true\r\nBundle-Version: 4.5.6\r\n\r\nName: ignored\r\nBundle-Version: 9\r\n", "pkg:maven/org.example/bundle@4.5.6"},
		{"module-1.2.jar", "Automatic-Module-Name: org.module\n", "pkg:maven/org.module/module@1.2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := gapZIP(t, map[string][]byte{"META-INF/MANIFEST.MF": []byte(tc.manifest)})
			pkgs, _ := catalog([]File{{Path: tc.name, Data: data}}, nil)
			if len(pkgs) != 1 || pkgs[0].PURL != tc.want {
				t.Fatalf("packages = %+v", pkgs)
			}
		})
	}
	data := gapZIP(t, map[string][]byte{
		"META-INF/maven/org.real/real/pom.properties": []byte("groupId=org.real\nartifactId=real\nversion=1\n"),
		"META-INF/MANIFEST.MF":                        []byte("Implementation-Title: wrong\nImplementation-Version: 2\n"),
	})
	pkgs, _ := catalog([]File{{Path: "wrong-3.jar", Data: data}}, nil)
	if len(pkgs) != 1 || pkgs[0].PURL != "pkg:maven/org.real/real@1" {
		t.Fatalf("packages = %+v", pkgs)
	}
}

func TestInventoryJavaLimits(t *testing.T) {
	data := gapZIP(t, map[string][]byte{"META-INF/maven/g/a/pom.properties": []byte("groupId=g\nartifactId=a\nversion=1\n")})
	t.Run("size", func(t *testing.T) {
		old := maxJavaArchive
		maxJavaArchive = int64(len(data))
		t.Cleanup(func() { maxJavaArchive = old })
		root := t.TempDir()
		gapWrite(t, root, "fits.jar", data)
		gapWrite(t, root, "oversize.jar", append(append([]byte(nil), data...), 0))
		for _, workers := range []int{1, 4} {
			r, err := Directory(root, "test", Options{SkipBinaries: true, Workers: workers})
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Packages) != 1 || r.Packages[0].Source != "fits.jar" || r.Scan.MetadataSkipped != 1 || !r.Scan.Partial {
				t.Fatalf("result = %+v, scan = %+v", r.Packages, r.Scan)
			}
		}
		file := writeTemp(t, "size.tar", buildTar(t, []tarEntry{{name: "fits.jar", data: data}, {name: "oversize.jar", data: append(append([]byte(nil), data...), 0)}}))
		r, err := Archive(file, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Packages) != 1 || r.Scan == nil || r.Scan.MetadataSkipped != 1 {
			t.Fatalf("packages=%+v scan=%+v", r.Packages, r.Scan)
		}
	})
	t.Run("depth", func(t *testing.T) {
		nested := data
		for i := 0; i < 4; i++ {
			nested = gapZIP(t, map[string][]byte{"lib/inner.jar": nested})
		}
		var pkgs []Package
		skipped, failures := scanJavaArchive(bytes.NewReader(nested), int64(len(nested)), File{Path: "outer.jar"}, func(p Package) { pkgs = append(pkgs, p) })
		if len(pkgs) != 0 || skipped != 1 || failures != 0 {
			t.Fatalf("packages=%+v skipped=%d failures=%d", pkgs, skipped, failures)
		}
		nested = data
		for i := 0; i < 3; i++ {
			nested = gapZIP(t, map[string][]byte{"BOOT-INF/lib/inner.jar": nested})
		}
		pkgs = nil
		skipped, failures = scanJavaArchive(bytes.NewReader(nested), int64(len(nested)), File{Path: "outer.jar"}, func(p Package) { pkgs = append(pkgs, p) })
		if len(pkgs) != 1 || skipped != 0 || failures != 0 {
			t.Fatalf("packages=%+v skipped=%d failures=%d", pkgs, skipped, failures)
		}
	})
	t.Run("cumulative", func(t *testing.T) {
		old := maxJavaExpanded
		maxJavaExpanded = int64(len(data))
		t.Cleanup(func() { maxJavaExpanded = old })
		nested := gapZIP(t, map[string][]byte{"lib/inner.jar": data})
		var pkgs []Package
		skipped, failures := scanJavaArchive(bytes.NewReader(nested), int64(len(nested)), File{Path: "outer.jar"}, func(p Package) { pkgs = append(pkgs, p) })
		if len(pkgs) != 0 || skipped != 1 || failures != 0 {
			t.Fatalf("packages=%+v skipped=%d failures=%d", pkgs, skipped, failures)
		}
	})
}

func TestInventoryJavaImageSpoolAndLinks(t *testing.T) {
	old := maxFileMetadata
	maxFileMetadata = 64
	t.Cleanup(func() { maxFileMetadata = old })
	data := gapZIP(t, map[string][]byte{"META-INF/maven/g/a/pom.properties": []byte("groupId=g\nartifactId=a\nversion=1\n")})
	for _, target := range []string{"lib/original.jar", "lib/opaque.dat"} {
		t.Run(target, func(t *testing.T) {
			layer := buildTar(t, []tarEntry{
				{name: target, data: data},
				{name: "lib/hard.jar", typeflag: tar.TypeLink, link: target},
				{name: "lib/sym.jar", typeflag: tar.TypeSymlink, link: path.Base(target)},
			})
			r, err := Archive(writeTemp(t, "links.tar", layer), Options{})
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Packages) != 1 || !strings.Contains(r.Packages[0].Source, "lib/hard.jar") || !strings.Contains(r.Packages[0].Source, "lib/sym.jar") {
				t.Fatalf("packages=%+v", r.Packages)
			}
			for _, f := range r.Files {
				if isJavaArchive(f.Path) && f.Data != nil {
					t.Errorf("retained archive %s", f.Path)
				}
			}
		})
	}
	u := newUnpacker(context.Background(), Options{})
	defer u.Close()
	if err := u.applyTar(bytes.NewReader(buildTar(t, []tarEntry{{name: "gone.jar", data: data}})), "one"); err != nil {
		t.Fatal(err)
	}
	temp := u.tempDir
	if temp == "" || u.rpmFiles["gone.jar"] == "" {
		t.Fatal("archive was not spooled")
	}
	if err := u.applyTar(bytes.NewReader(buildTar(t, []tarEntry{{name: ".wh.gone.jar"}})), "two"); err != nil {
		t.Fatal(err)
	}
	if len(u.rpmFiles) != 0 {
		t.Fatal("whiteout retained spool")
	}
	u.Close()
	if _, err := os.Stat(temp); !os.IsNotExist(err) {
		t.Fatalf("temp directory remains: %v", err)
	}
}

func TestInventoryInstalledNPMCountLimit(t *testing.T) {
	old := maxInstalledNPM
	maxInstalledNPM = 2
	t.Cleanup(func() { maxInstalledNPM = old })
	root := t.TempDir()
	var entries []tarEntry
	for _, name := range []string{"a", "b", "c", "d"} {
		p := "node_modules/" + name + "/package.json"
		data := []byte(`{"name":"` + name + `","version":"1.0"}`)
		gapWrite(t, root, p, data)
		entries = append(entries, tarEntry{name: p, data: data})
	}
	for _, workers := range []int{1, 4} {
		r, err := Directory(root, "test", Options{Workers: workers, SkipBinaries: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Packages) != 2 || r.Packages[0].Name != "a" || r.Packages[1].Name != "b" || r.Scan.MetadataSkipped != 2 {
			t.Fatalf("packages=%+v scan=%+v", r.Packages, r.Scan)
		}
	}
	r, err := Archive(writeTemp(t, "npm.tar", buildTar(t, entries)), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Packages) != 2 || r.Scan == nil || r.Scan.MetadataSkipped != 2 {
		t.Fatalf("packages=%+v scan=%+v", r.Packages, r.Scan)
	}
}

// A sparse prefix represents a large executable JAR without allocating or
// writing a large fixture. ZIP offsets point directly at the tiny metadata.
func TestInventoryLargeJavaReaderAt(t *testing.T) {
	root := t.TempDir()
	f, err := os.Create(filepath.Join(root, "large.jar"))
	if err != nil {
		t.Fatal(err)
	}
	const offset = 128 << 20
	if _, err := f.Seek(offset, 0); err != nil {
		f.Close()
		t.Fatal(err)
	}
	z := zip.NewWriter(f)
	z.SetOffset(offset)
	w, err := z.Create("META-INF/maven/g/a/pom.properties")
	if err != nil {
		f.Close()
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("groupId=g\nartifactId=a\nversion=1\n")); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	for _, workers := range []int{1, 4} {
		r, err := Directory(root, "test", Options{Workers: workers, SkipBinaries: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Packages) != 1 || r.Packages[0].PURL != "pkg:maven/g/a@1" || r.Scan.MetadataSkipped != 0 {
			t.Fatalf("packages=%+v scan=%+v", r.Packages, r.Scan)
		}
	}
	rd, err := os.Open(filepath.Join(root, "large.jar"))
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	st, err := rd.Stat()
	if err != nil {
		t.Fatal(err)
	}
	counter := &gapReaderAt{ReaderAt: rd}
	count := 0
	skipped, failures := scanJavaArchive(counter, st.Size(), File{Path: "large.jar"}, func(Package) { count++ })
	if count != 1 || skipped != 0 || failures != 0 || counter.bytes > 128<<10 {
		t.Fatalf("count=%d skipped=%d errors=%d bytes=%d", count, skipped, failures, counter.bytes)
	}
}

type gapReaderAt struct {
	io.ReaderAt
	bytes int
}

func (r *gapReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := r.ReaderAt.ReadAt(p, off)
	r.bytes += n
	return n, err
}

func TestInventoryJavaNestedFilenameAndCorruption(t *testing.T) {
	nested := gapZIP(t, map[string][]byte{"nested-name-1.2.jar": gapZIP(t, map[string][]byte{"x": []byte("x")})})
	pkgs, _ := catalog([]File{{Path: "outer.ear", Data: nested}}, nil)
	if len(pkgs) != 1 || pkgs[0].PURL != "pkg:generic/nested-name@1.2" || pkgs[0].Source != "outer.ear!nested-name-1.2.jar" {
		t.Fatalf("packages=%+v", pkgs)
	}
	root := t.TempDir()
	gapWrite(t, root, "broken-1.jar", []byte("not a zip"))
	r, err := Directory(root, "test", Options{SkipBinaries: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Packages) != 0 || r.Scan.SkippedErrors != 1 || !r.Scan.Partial {
		t.Fatalf("packages=%+v scan=%+v", r.Packages, r.Scan)
	}
}

func TestInstalledNPMAndGemspecEvidence(t *testing.T) {
	var got []Package
	add := func(p Package) { got = append(got, p) }
	scanInstalledNPM(File{Path: "usr/lib/node_modules/abbrev/package.json", Data: []byte(`{"name":"abbrev","version":"3.0.1"}`)}, add)
	scanInstalledGemspec(File{Path: "usr/local/lib/ruby/gems/3.3.0/specifications/base64-0.2.0.gemspec", Data: []byte("Gem::Specification.new do |s|\n  s.name = \"base64\"\n  s.version = \"0.2.0\"\nend\n")}, add)
	if len(got) != 2 || got[0].Evidence != "installed" || got[1].Evidence != "installed" {
		t.Fatalf("evidence not recorded: %+v", got)
	}
}
