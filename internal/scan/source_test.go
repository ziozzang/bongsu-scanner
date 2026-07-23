package scan

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func tarData(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for name, data := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestDockerArchiveCatalogAndWhiteout(t *testing.T) {
	layer1 := tarData(t, map[string][]byte{
		"var/lib/dpkg/status": []byte("Package: libc6\nStatus: install ok installed\nVersion: 2.39-1\nArchitecture: amd64\n\n"),
		"deleted.txt":         []byte("gone"),
	})
	layer2 := tarData(t, map[string][]byte{
		".wh.deleted.txt":      {},
		"app/requirements.txt": []byte("requests==2.32.3\n"),
		"etc/os-release":       []byte("ID=debian\nVERSION_ID=\"12\"\n"),
	})
	manifest, _ := json.Marshal([]map[string]any{{"Config": "config.json", "RepoTags": []string{"test:latest"}, "Layers": []string{"l1/layer.tar", "l2/layer.tar"}}})
	outer := tarData(t, map[string][]byte{
		"manifest.json": manifest,
		"config.json":   []byte(`{}`),
		"l1/layer.tar":  layer1,
		"l2/layer.tar":  layer2,
	})
	p := filepath.Join(t.TempDir(), "image.tar")
	if err := os.WriteFile(p, outer, 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := Archive(p, Options{IncludeFileHashes: true, Now: time.Unix(1, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if r.SourceType != "docker-archive" || len(r.Layers) != 2 || r.OSName != "debian" || r.OSVersion != "12" {
		t.Fatalf("unexpected result: type=%s layers=%d os=%s/%s", r.SourceType, len(r.Layers), r.OSName, r.OSVersion)
	}
	for _, f := range r.Files {
		if f.Path == "deleted.txt" {
			t.Fatal("whiteout did not delete prior file")
		}
	}
	got := map[string]string{}
	for _, p := range r.Packages {
		got[p.Name] = p.Version
	}
	if got["libc6"] != "2.39-1" || got["requests"] != "2.32.3" {
		t.Fatalf("catalog = %#v", got)
	}
}

func TestDirectoryGoAndNPMCatalog(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "go.mod"), []byte("module x\nrequire example.com/mod v1.2.3\n"), 0o644)
	os.WriteFile(filepath.Join(d, "package-lock.json"), []byte(`{"packages":{"node_modules/a":{"name":"a","version":"4.5.6"}}}`), 0o644)
	var events []Progress
	r, err := Directory(d, "test", Options{IncludeFileHashes: true, Verbose: true, Progress: func(p Progress) {
		events = append(events, p)
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Packages) != 2 {
		t.Fatalf("packages = %#v", r.Packages)
	}
	stages := map[string]bool{}
	for _, event := range events {
		stages[event.Stage] = true
	}
	for _, want := range []string{"walk", "file", "catalog", "package"} {
		if !stages[want] {
			t.Errorf("progress stage %q missing: %#v", want, events)
		}
	}
}
