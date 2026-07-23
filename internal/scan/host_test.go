package scan

import "testing"

func TestParseHostHardwareMetadata(t *testing.T) {
	cpu := []byte("processor : 0\nmodel name : Test CPU 9000\n")
	if got := parseCPUModel(cpu); got != "Test CPU 9000" {
		t.Fatalf("CPU model = %q", got)
	}
	memory := []byte("MemTotal:       16384 kB\nMemFree: 10 kB\n")
	if got := parseMemoryBytes(memory); got != 16384*1024 {
		t.Fatalf("memory = %d", got)
	}
}

func TestCollectHostMetadata(t *testing.T) {
	got := collectHostMetadata("test-os", "1")
	if got.OperatingSystem != "test-os" || got.OSVersion != "1" {
		t.Fatalf("OS metadata = %#v", got)
	}
	if got.Architecture == "" || got.CPUCount < 1 || got.MemoryBytes == 0 {
		t.Fatalf("hardware metadata incomplete: %#v", got)
	}
}

func TestHostPackageSourcesBecomeAbsolute(t *testing.T) {
	packages := []Package{{Name: "a", Source: "home/foo/go.mod"}, {Name: "b", Source: "/var/lib/dpkg/status"}}
	makeHostPackageSourcesAbsolute(packages)
	if packages[0].Source != "/home/foo/go.mod" || packages[1].Source != "/var/lib/dpkg/status" {
		t.Fatalf("sources = %#v", packages)
	}
}
