package deploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestR27DockerRequiresOptIn(t *testing.T) {
	if os.Getenv("R27_DOCKER_GATE_CHILD") == "1" {
		TestDockerDefaultUIDDirectoryScan(t)
		return
	}
	bin := t.TempDir()
	marker := filepath.Join(bin, "called")
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte("#!/bin/sh\ntouch '"+marker+"'\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestR27DockerRequiresOptIn$", "-test.v")
	cmd.Env = append(os.Environ(), "R27_DOCKER_GATE_CHILD=1", "BSCAN_DOCKER_TESTS=", "PATH="+bin+":"+os.Getenv("PATH"), "GORACE=atexit_sleep_ms=0")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "BSCAN_DOCKER_TESTS=1") {
		t.Fatalf("gate: %v %s", err, out)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("docker invoked without opt-in")
	}
}

func TestR27BuildVersionAndDockerCI(t *testing.T) {
	for _, version := range []string{"", "9.8.7"} {
		args := []string{"-s", "-n", "-f", "../Makefile", "build"}
		want := "0.6.0-dev"
		if version != "" {
			args = append(args, "VERSION="+version)
			want = version
		}
		out, err := exec.Command("make", args...).CombinedOutput()
		if err != nil || !strings.Contains(string(out), "-X main.version="+want) {
			t.Fatalf("build version: %v %s", err, out)
		}
	}
	requireText(t, "../.github/workflows/ci.yml", "BSCAN_DOCKER_TESTS: '1'", "go test -race -count=1 -p 2 ./deploy -run '^TestDockerDefaultUIDDirectoryScan$'")
}
