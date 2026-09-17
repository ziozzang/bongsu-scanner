package scan

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBinaryClassificationDirectory(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"bin/python3":         "\x7fELF\x00Python 3.12.14\x00",
		"opt/python3":         "\x7fELF\x00Python 3.12.14\x00",
		"lib/libcrypto.so.3":  "\x7fELF\x00OpenSSL 3.0.13 30 Jan 2024\x00",
		"opt/jre/release":     "JAVA_VERSION=\"21.0.4\"\nIMPLEMENTOR=\"Eclipse Adoptium\"\n",
		"var/lib/dpkg/status": "Package: python\nStatus: install ok installed\nVersion: 3.12.14\nArchitecture: amd64\n\n",
	})
	for _, p := range []string{"bin/python3", "opt/python3"} {
		if err := os.Chmod(filepath.Join(root, p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, workers := range []int{1, 4} {
		r, err := DirectoryContext(context.Background(), root, "fixture", Options{Workers: workers})
		if err != nil {
			t.Fatal(err)
		}
		by := map[string]Package{}
		for _, p := range r.Packages {
			by[p.PURL] = p
		}
		p := by["pkg:generic/python@3.12.14"]
		if p.Evidence != "binary" || p.Source != "bin/python3;opt/python3" || p.CPE != "cpe:2.3:a:python:python:3.12.14:*:*:*:*:*:*:*" {
			t.Errorf("workers=%d: python = %+v", workers, p)
		}
		if by["pkg:deb/debian/python@3.12.14?arch=amd64"].Name != "python" {
			t.Error("OS package was suppressed")
		}
		if by["pkg:generic/openssl@3.0.13"].Source != "lib/libcrypto.so.3" {
			t.Error("non-executable shared library missing")
		}
		if p := by["pkg:generic/temurin@21.0.4"]; p.Evidence != "binary" || p.CPE != "cpe:2.3:a:eclipse:temurin:21.0.4:*:*:*:*:*:*:*" {
			t.Errorf("JRE release = %+v", p)
		}
	}
	r, err := DirectoryContext(context.Background(), root, "fixture", Options{SkipBinaries: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range r.Packages {
		if p.Evidence == "binary" {
			t.Fatalf("SkipBinaries: %+v", p)
		}
	}
}

func TestBinaryClassificationArchive(t *testing.T) {
	u := newUnpacker(context.Background(), Options{})
	defer u.Close()
	layer := buildTar(t, []tarEntry{
		{name: "bin/busybox", data: []byte("\x7fELF\x00BusyBox v1.36.1\x00"), mode: 0o755},
		{name: "lib/libcrypto.so.3", data: []byte("\x7fELF\x00OpenSSL 3.0.13 30 Jan 2024\x00"), mode: 0o644},
	})
	if err := u.applyTar(bytes.NewReader(layer), "base"); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"bin/busybox", "lib/libcrypto.so.3"} {
		p := u.binaries[path]
		if len(p) != 1 || p[0].Source != path || p[0].Layer != "base" || p[0].Evidence != "binary" {
			t.Errorf("%s = %+v", path, p)
		}
	}
	upper := buildTar(t, []tarEntry{{name: "bin/.wh.busybox"}, {name: "lib/libcrypto.so.3", data: []byte("replaced")}})
	if err := u.applyTar(bytes.NewReader(upper), "upper"); err != nil {
		t.Fatal(err)
	}
	for name := range u.binaries {
		if strings.Contains(name, "busybox") || strings.Contains(name, "crypto") {
			t.Errorf("stale discovery: %s", name)
		}
	}
}

func TestBinaryClassificationBudgetHooks(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "curl")
	data := []byte("\x7fELF\x00curl 8.9.1\x00")
	if err := os.WriteFile(file, data, 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := newWalkState(context.Background(), root, Options{}, false)
	w.binaryBudget.count.Store(maxClassifiedBinaries)
	w.probeBinary(f, "curl", int64(len(data)))
	if len(w.binaries.seen) != 0 {
		t.Fatal("walk ignored binary cap")
	}
	if m := w.metadata(); !m.Partial || !strings.Contains(m.LimitReached, "max-binaries") {
		t.Fatalf("missing cap metadata: %+v", m)
	}
	u := newUnpacker(context.Background(), Options{})
	defer u.Close()
	u.binaryBudget.count.Store(maxClassifiedBinaries)
	u.recordBinary("curl", "", data)
	if len(u.binaries) != 0 {
		t.Fatal("archive ignored binary cap")
	}
}

func TestBinaryProbeBudgetSurvivesWalkReplay(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"a/go.mod": "module example.com/replay\n",
		"b/curl":   "\x7fELF\x00curl 8.9.1\x00",
	})
	if err := os.Chmod(filepath.Join(root, "b/curl"), 0o755); err != nil {
		t.Fatal(err)
	}
	opts := Options{Workers: 4, MaxTotalBytes: 1}
	w := newWalkState(context.Background(), root, opts, false)
	w.workers = 4
	budget := w.binaryBudget
	budget.count.Store(maxClassifiedBinaries)
	if err := walkTree(w.ctx, root, opts, w); err != nil {
		t.Fatal(err)
	}
	if w.workers != 1 {
		t.Fatal("fixture did not trigger sequential replay")
	}
	if w.binaryBudget != budget || len(w.binaries.seen) != 0 {
		t.Fatal("metadata-budget replay reset the per-scan binary budget")
	}
}
