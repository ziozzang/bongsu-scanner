package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestR27ConfigFlagPrecedence(t *testing.T) {
	t.Setenv("BONGSU_HOME", t.TempDir())
	t.Setenv("BONGSU_NO_UPDATE_CHECK", "1")
	dir := t.TempDir()
	t.Chdir(dir)
	for _, name := range []string{"env", "flag"} {
		if err := os.WriteFile(filepath.Join(dir, name+".yaml"), []byte("signer: "+name+"\noffline: true\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("BONGSU_CONFIG", "env.yaml")
	for _, name := range []string{"env", "flag"} {
		args := []string{"config", "show"}
		if name == "flag" {
			args = append([]string{"--config", "flag.yaml"}, args...)
		}
		out, stderr, err := captureCommandStreams(t, func() error { return run(context.Background(), args) })
		if err != nil || !strings.Contains(out, filepath.Join(dir, name+".yaml")) || !strings.Contains(out, "signer: \""+name+"\"") {
			t.Fatalf("%s: %s %s %v", name, out, stderr, err)
		}
		if os.Getenv("BONGSU_CONFIG") != "env.yaml" {
			t.Fatal("flag did not restore environment")
		}
	}
}

func TestR27QuietProgressWarning(t *testing.T) {
	for _, format := range []string{"text", "json"} {
		t.Run(format, func(t *testing.T) {
			restore, err := applyGlobalFlags(globalFlags{quiet: true, logFormat: format})
			if err != nil {
				t.Fatal(err)
			}
			defer restore()
			out, stderr, err := captureCommandStreams(t, func() error {
				_, err := (logWriter{stage: "db"}).Write([]byte("ordinary progress\nWARNING: redhat-vex remaining=2 missing=1\n"))
				return err
			})
			if err != nil || out != "" || strings.Contains(stderr, "ordinary progress") || !strings.Contains(stderr, "WARNING: redhat-vex remaining=2 missing=1") {
				t.Fatalf("out=%q stderr=%q err=%v", out, stderr, err)
			}
			if format == "json" && !strings.Contains(stderr, `"level":"warn"`) {
				t.Fatal(stderr)
			}
		})
	}
}

func TestR27DefaultVersion(t *testing.T) {
	out, stderr, code := polishCLI(t, t.TempDir(), "version")
	if code != 0 || !strings.Contains(out, "0.6.0-dev") {
		t.Fatalf("version: code=%d out=%q stderr=%q", code, out, stderr)
	}
}
