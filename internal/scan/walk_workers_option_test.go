package scan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Options.Workers selects the traversal parallelism; results must not depend on it.
func TestWorkersOptionSelectsParallelism(t *testing.T) {
	t.Setenv("BONGSU_WALK_WORKERS", "")
	root := t.TempDir()
	for i := 0; i < 12; i++ {
		dir := filepath.Join(root, "d", string(rune('a'+i)))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("pkg"+string(rune('a'+i))+"==1.0\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, workers := range []int{0, 1, 3} {
		w := newWalkState(context.Background(), root, Options{Workers: workers}, false)
		want := workers
		if workers == 0 {
			want = w.workers // default derived from CPU count
			if want < 1 {
				t.Fatalf("default workers = %d", want)
			}
		}
		if w.workers != want {
			t.Fatalf("Workers=%d → walker uses %d", workers, w.workers)
		}
	}
	seq, err := Directory(root, "fixture", Options{Workers: 1})
	if err != nil {
		t.Fatal(err)
	}
	par, err := Directory(root, "fixture", Options{Workers: 4})
	if err != nil {
		t.Fatal(err)
	}
	if len(seq.Packages) != 12 || len(par.Packages) != len(seq.Packages) {
		t.Fatalf("packages: sequential=%d parallel=%d", len(seq.Packages), len(par.Packages))
	}
	for i := range seq.Packages {
		if seq.Packages[i].PURL != par.Packages[i].PURL || seq.Packages[i].Source != par.Packages[i].Source {
			t.Fatalf("package %d differs: %+v vs %+v", i, seq.Packages[i], par.Packages[i])
		}
	}
}
