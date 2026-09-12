package main

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	hashutil "github.com/ziozzang/bongsu-scanner/internal/hash"
	"github.com/ziozzang/bongsu-scanner/internal/scan"
)

func captureBatchStderr(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	old := os.Stderr
	os.Stderr = f
	defer func() { os.Stderr = old }()
	runErr := fn()
	b, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(b), runErr
}

func TestBatchDistinctOutputs(t *testing.T) {
	for _, names := range [][]string{
		{"rootfs", "rootfs"},
		{"root fs", "root_fs"},
		{"rootfs", "rootfs", "rootfs-1"},
		{"first", "second"},
		{"host:container:x", "host.container-x.container-x"},
		{"host:container:x", "host_container_x"},
	} {
		t.Run(strings.Join(names, "+"), func(t *testing.T) {
			t.Setenv("BONGSU_HOME", t.TempDir())
			var targets []string
			for i, name := range names {
				target := filepath.Join(t.TempDir(), name)
				if err := os.Mkdir(target, 0o755); err != nil {
					t.Fatal(err)
				}
				manifest := fmt.Sprintf("module fixture\nrequire example.com/batch-marker%d v1.0.0\n", i)
				if err := os.WriteFile(filepath.Join(target, "go.mod"), []byte(manifest), 0o644); err != nil {
					t.Fatal(err)
				}
				targets = append(targets, target)
			}
			var previous []string
			for attempt := range 2 {
				output := t.TempDir()
				args := append([]string{"--no-sign", "--jobs", "2", "--output", output}, targets...)
				log, err := captureBatchStderr(t, func() error { return cmdBatch(context.Background(), args) })
				if err != nil {
					t.Fatal(err)
				}
				entries, err := os.ReadDir(output)
				if err != nil {
					t.Fatal(err)
				}
				if len(entries) != 2*len(targets) {
					t.Fatalf("outputs = %d, want %d; log: %s", len(entries), 2*len(targets), log)
				}
				var paths []string
				seen := make([]int, len(targets))
				for _, entry := range entries {
					paths = append(paths, entry.Name())
					b, err := os.ReadFile(filepath.Join(output, entry.Name()))
					if err != nil {
						t.Fatal(err)
					}
					for i := range targets {
						if bytes.Contains(b, []byte(fmt.Sprintf("batch-marker%d", i))) {
							seen[i]++
						}
					}
				}
				for i, count := range seen {
					if count != 2 {
						t.Errorf("target %d appears in %d SBOMs, want 2", i, count)
					}
				}
				if attempt > 0 && strings.Join(paths, "\n") != strings.Join(previous, "\n") {
					t.Fatalf("output names are not deterministic: %v vs %v", paths, previous)
				}
				previous = paths
				if names[0] == "first" || names[1] == "host.container-x.container-x" {
					for _, name := range names {
						if _, err := os.Stat(filepath.Join(output, safeName(name)+".spdx.json")); err != nil {
							t.Fatal(err)
						}
					}
				} else if !strings.Contains(log, "[batch:collision]") {
					t.Fatalf("missing collision log: %s", log)
				}
			}
		})
	}
}

func TestBatchRejectsDuplicatePathsBeforeScanning(t *testing.T) {
	for _, alias := range []string{"identical", "relative", "dot", "symlink"} {
		t.Run(alias, func(t *testing.T) {
			t.Setenv("BONGSU_HOME", t.TempDir())
			root := t.TempDir()
			target := filepath.Join(root, "rootfs")
			if err := os.Mkdir(target, 0o755); err != nil {
				t.Fatal(err)
			}
			other := target
			switch alias {
			case "relative":
				t.Chdir(root)
				other = "rootfs"
			case "dot":
				other += "/."
			case "symlink":
				other = filepath.Join(root, "alias")
				if err := os.Symlink(target, other); err != nil {
					t.Fatal(err)
				}
			}
			output := filepath.Join(t.TempDir(), "output")
			log, err := captureBatchStderr(t, func() error {
				return cmdBatch(context.Background(), []string{"--no-sign", "--output", output, target, other})
			})
			if err == nil || !strings.Contains(err.Error(), "duplicate target") {
				t.Fatalf("duplicate path error = %v", err)
			}
			if strings.Contains(log, "[scan:start]") {
				t.Fatalf("scanned before duplicate validation: %s", log)
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatalf("output created before duplicate validation: %v", err)
			}
		})
	}
}

func TestScanOutputContainerNaming(t *testing.T) {
	for _, tc := range []struct {
		name, sourceType, batchBase string
		hostContainers              bool
		want                        string
	}{
		{"literal directory", "directory", "", true, "host_container_x"},
		{"standalone container", "container", "", false, "host_container_x"},
		{"host container", "container", "", true, "host.container-x"},
		{"batch directory", "directory", "host_container_x", true, "host_container_x"},
		{"batch standalone container", "container", "host_container_x", false, "host_container_x"},
		{"batch host container", "container", "host-2", true, "host-2.container-x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := scanFlags{format: "spdx", output: t.TempDir(), noSign: true,
				batchOutputBase: tc.batchBase, hostContainers: tc.hostContainers}
			paths, err := writeScanOutputs(scan.Result{Name: "host:container:x", SourceType: tc.sourceType}, f)
			if err != nil {
				t.Fatal(err)
			}
			if len(paths) != 1 || filepath.Base(paths[0]) != tc.want+".spdx.json" {
				t.Fatalf("outputs = %v, want %s.spdx.json", paths, tc.want)
			}
		})
	}
}

func TestScanOutputsRejectFinalContainerPathCollision(t *testing.T) {
	for _, format := range []string{"both", "spdx", "cyclonedx"} {
		t.Run(format, func(t *testing.T) {
			f := scanFlags{format: format, output: t.TempDir(), noSign: true, outputPaths: &scanOutputPaths{}}
			hostFlags := f
			hostFlags.hostContainers = true
			hostFlags.batchOutputBase = "host"
			directoryFlags := f
			directoryFlags.batchOutputBase = "host.container-x"
			errs := make(chan error, 2)
			go func() {
				_, err := writeScanOutputs(scan.Result{Name: "host:container:x", SourceType: "container"}, hostFlags)
				errs <- err
			}()
			go func() {
				_, err := writeScanOutputs(scan.Result{Name: "host.container-x", SourceType: "directory"}, directoryFlags)
				errs <- err
			}()
			var successes, collisions int
			for range 2 {
				err := <-errs
				if err == nil {
					successes++
				} else if strings.Contains(err.Error(), "output path collision") {
					collisions++
				} else {
					t.Errorf("unexpected error: %v", err)
				}
			}
			if successes != 1 || collisions != 1 {
				t.Fatalf("successes=%d collisions=%d; want one of each", successes, collisions)
			}
			// The reservation must also protect completed files from later results.
			entries, err := os.ReadDir(f.output)
			if err != nil {
				t.Fatal(err)
			}
			before := make(map[string][]byte)
			for _, entry := range entries {
				path := filepath.Join(f.output, entry.Name())
				before[path], err = os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := writeScanOutputs(scan.Result{Name: "another result"}, directoryFlags); err == nil {
				t.Fatal("overwriting a completed result succeeded")
			}
			for path, want := range before {
				got, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("output changed after collision: %s (%v)", path, err)
				}
			}
		})
	}
}

func TestScanOutputsReserveArchiveManifestPaths(t *testing.T) {
	source := filepath.Join(t.TempDir(), "archive.tar")
	if err := os.WriteFile(source, []byte("fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := scanFlags{format: "both", output: t.TempDir(), noSign: true, outputPaths: &scanOutputPaths{}}
	r := scan.Result{Name: "root", Source: source, SourceType: "archive",
		Layers: []scan.File{{Path: "layer.tar", SHA256: strings.Repeat("0", 64)}}}
	if _, err := writeScanOutputs(r, f); err != nil {
		t.Fatal(err)
	}
	r.Name = "root.layers"
	r.Layers = nil
	if _, err := writeScanOutputs(r, f); err == nil || !strings.Contains(err.Error(), "root.layers.sha256") {
		t.Fatalf("overlapping manifest error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(f.output, "root.layers.spdx.json")); !os.IsNotExist(err) {
		t.Fatalf("output written before all final paths were reserved: %v", err)
	}
}

func TestBatchArchiveCollisionKeepsManifestsAndSignaturesValid(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	if err := cmdInit([]string{"--signer", "batch-test"}); err != nil {
		t.Fatal(err)
	}
	var targets []string
	for i := range 2 {
		var archive bytes.Buffer
		tw := tar.NewWriter(&archive)
		data := []byte(fmt.Sprintf("ID=fixture%d\n", i))
		if err := tw.WriteHeader(&tar.Header{Name: "etc/os-release", Mode: 0o644, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "rootfs.tar")
		if err := os.WriteFile(target, archive.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		targets = append(targets, target)
	}
	output := t.TempDir()
	args := append([]string{"--sign", "--jobs", "2", "--output", output}, targets...)
	if err := cmdBatch(context.Background(), args); err != nil {
		t.Fatal(err)
	}
	manifests, err := filepath.Glob(filepath.Join(output, "*.sha256"))
	if err != nil || len(manifests) != 2 {
		t.Fatalf("manifests = %v, error = %v", manifests, err)
	}
	for _, manifest := range manifests {
		if err := hashutil.Verify(manifest); err != nil {
			t.Fatal(err)
		}
		if err := cmdCheck(context.Background(), []string{manifest + ".sig"}, true); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRunSubcommandHelpSucceeds(t *testing.T) {
	for _, command := range [][]string{{"scan"}, {"match"}, {"db", "update"}, {"batch"}, {"init"}, {"hash"}, {"sign"}, {"verify"}, {"scramble", "encrypt"}, {"update"}} {
		t.Run(strings.Join(command, " "), func(t *testing.T) {
			for _, help := range []string{"--help", "-h"} {
				args := append(append([]string(nil), command...), help)
				output, err := captureBatchStderr(t, func() error { return run(context.Background(), args) })
				if err != nil || exitCode(err) != 0 {
					t.Fatalf("%v: error = %v, exit = %d", args, err, exitCode(err))
				}
				if !strings.Contains(output, "Usage of ") || strings.Contains(output, "flag: help requested") {
					t.Fatalf("unexpected help output: %s", output)
				}
			}
		})
	}
	_, err := captureBatchStderr(t, func() error {
		return run(context.Background(), []string{"scan", "--invalid-flag"})
	})
	if err == nil || exitCode(err) != 1 {
		t.Fatalf("invalid flag error = %v, exit = %d", err, exitCode(err))
	}
}
