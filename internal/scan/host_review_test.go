package scan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func reviewDockerScript(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte("#!/bin/sh\n"+script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestReviewContainerEnumerationFailure(t *testing.T) {
	reviewDockerScript(t, "echo 'daemon unavailable' >&2\nexit 1\n")
	for _, optional := range []bool{false, true} {
		var warnings []string
		r, err := TargetAll(context.Background(), "host", Options{
			HostRoot: t.TempDir(), IncludeContainers: true, ContainersOptional: optional,
			SkipBinaries: true, NoHostMetadata: true,
			Progress: func(p Progress) { warnings = append(warnings, p.Message) },
		})
		if (err == nil) != optional {
			t.Fatalf("optional=%t: err=%v", optional, err)
		}
		if len(r) != 1 || r[0].SourceType != "host" || !containsString(warnings, "warning: cannot list running containers") {
			t.Fatalf("host/warning lost: results=%v warnings=%v", r, warnings)
		}
	}
}

func TestReviewContainerNamesAndCommand(t *testing.T) {
	// Reject -q like a daemon that would otherwise suppress the names.
	reviewDockerScript(t, `
test "$#" = 4 && test "$1" = ps && test "$2" = --no-trunc && test "$3" = --format || exit 2
test "$4" = '{{.ID}}	{{.Names}}' || exit 3
printf 'abc123def456789\t/web\n0123456789abcdef0123\t\nfeed\tone,two\n'
`)
	list, err := runningContainers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 || list[0].id != "abc123def456789" || list[0].name != "web" || list[1].name != "0123456789ab" || list[2].name != "one" {
		t.Fatalf("containers = %+v", list)
	}
}

func TestReviewContainerResultNames(t *testing.T) {
	export := buildTar(t, []tarEntry{{name: "etc/os-release", data: []byte("ID=debian\n")}})
	fakeDocker(t, nil, export)
	// Wrap the existing inspect/export fixture with the enumeration command.
	docker := filepath.Join(strings.Split(os.Getenv("PATH"), string(os.PathListSeparator))[0], "docker")
	if err := os.Rename(docker, docker+"-delegate"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(docker, []byte("#!/bin/sh\nif [ \"$1\" = ps ]; then printf 'abc123def456789\\tweb\\n0123456789abcdef0123\\t\\n'; else exec \"$0-delegate\" \"$@\"; fi\n"), 0755); err != nil {
		t.Fatal(err)
	}
	results, err := TargetAll(context.Background(), "host", Options{HostRoot: t.TempDir(), IncludeContainers: true, NoHostMetadata: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 || results[1].Name != "host:container:web" || results[2].Name != "host:container:0123456789ab" {
		t.Fatalf("container names: %+v", results)
	}
}
