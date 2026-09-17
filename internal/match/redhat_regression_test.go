package match

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

func redHatLoaders(t *testing.T, data []byte, check func(*testing.T, Document)) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bom.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	for name, load := range map[string]func() (Document, error){
		"memory": func() (Document, error) { return Load(data) },
		"stream": func() (Document, error) { return LoadFile(path) },
	} {
		t.Run(name, func(t *testing.T) {
			d, err := load()
			if err != nil {
				t.Fatal(err)
			}
			check(t, d)
		})
	}
}

func TestRedHatMinorHostRelease(t *testing.T) {
	for _, tc := range []struct{ version, want string }{
		{"9.4", "9"}, {"10.0", "10.0"}, {"10.1", "10.1"},
		{"10.2", "10.2"}, {"10", ""}, {"11.1", "11.1"}, {"11", ""},
	} {
		for _, distro := range []string{"", "rhel-" + tc.version} {
			t.Run(tc.version+"/"+distro, func(t *testing.T) {
				data := []byte(fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"operating-system","name":"rhel","version":%q},{"bom-ref":"rpm","name":"example","version":"1","purl":"pkg:rpm/rhel/example?distro=%s"}]}`, tc.version, distro))
				redHatLoaders(t, data, func(t *testing.T, d Document) {
					if len(d.Subjects) != 1 || d.Subjects[0].Release != tc.want {
						t.Fatalf("subjects=%+v, want release %q", d.Subjects, tc.want)
					}
					if tc.want == "" {
						for _, coverage := range []map[string]map[string]bool{
							{"Red Hat": {"10.0": true}}, {"Red Hat": {"": true}},
						} {
							if got := subjectSkip(d.Subjects[0], coverage); got != "release-unknown" {
								t.Fatalf("skip=%q, coverage=%v", got, coverage)
							}
						}
					}
				})
			})
		}
	}
}

func TestRedHatMinorErrataBoundary(t *testing.T) {
	r100 := advisory("Red Hat:enterprise_linux:10.0", "kernel", "0:6.12.0-55.25.1.el10_0")
	r100.ID, r100.Aliases = "RHSA-2025:12662", []string{"CVE-2025-21727"}
	r101 := advisory("Red Hat:enterprise_linux:10.1", "kernel", "0:6.12.0-124.8.1.el10_1")
	r101.ID, r101.Aliases = "RHSA-2025:20095", []string{"CVE-2025-21727"}
	for _, tc := range []struct {
		version string
		want    int
	}{
		{"0:6.12.0-55.25.1.el10_0", 0},
		{"0:6.12.0-55.24.1.el10_0", 1},
	} {
		t.Run(tc.version, func(t *testing.T) {
			data := []byte(fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"operating-system","name":"rhel","version":"10.0"},{"bom-ref":"rpm","name":"kernel","version":%q,"purl":"pkg:rpm/rhel/kernel"}]}`, tc.version))
			redHatLoaders(t, data, func(t *testing.T, d Document) {
				report, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{r100, r101}}, d.Subjects, Options{})
				if err != nil || len(report.Findings) != tc.want || len(report.Skipped) != 0 || len(report.MissingCoverage) != 0 {
					t.Fatalf("report=%+v err=%v", report, err)
				}
			})
		})
	}
}

func TestRPMComponentVersionEpochMatching(t *testing.T) {
	for _, tc := range []struct {
		version, qualifier, wantVersion string
		findings                        int
	}{
		{"1.2-4.el9", "&epoch=1", "1:1.2-4.el9", 0},
		{"1.2-3.el9", "&epoch=1", "1:1.2-3.el9", 1},
		{"1.2-4.el9", "&epoch=0", "0:1.2-4.el9", 1},
		{"1.2-4.el9", "", "1.2-4.el9", 1},
		{"1.2-4.el9", "&epoch=bad", "1.2-4.el9", 1},
		{"1:1.2-4.el9", "&epoch=1", "1:1.2-4.el9", 0},
		{"2:1.2-4.el9", "&epoch=1", "2:1.2-4.el9", 0},
	} {
		t.Run(tc.version+tc.qualifier, func(t *testing.T) {
			data := []byte(fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"bom-ref":"rpm","name":"example","version":%q,"purl":"pkg:rpm/rhel/example@1.2-4.el9?distro=rhel-9%s"}]}`, tc.version, tc.qualifier))
			redHatLoaders(t, data, func(t *testing.T, d Document) {
				if len(d.Subjects) != 1 || d.Subjects[0].Version != tc.wantVersion {
					t.Errorf("subjects=%+v, want version %q", d.Subjects, tc.wantVersion)
				}
				r, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{advisory("Red Hat:enterprise_linux:9::baseos", "example", "1:1.2-4.el9")}}, d.Subjects, Options{})
				if err != nil || len(r.Findings) != tc.findings || len(r.Skipped) != 0 {
					t.Fatalf("report=%+v err=%v", r, err)
				}
			})
		})
	}
}

func TestCentOSStreamSpellings(t *testing.T) {
	for _, tc := range []struct{ namespace, distro, wantRelease string }{
		{"CentOS", "9", "centos-stream:9"},
		{"CENTOS", "9.4", "centos-stream:9"},
		{"centos", "centos-stream-9", "centos-stream:9"},
		{"CentOS", "centos-stream:9", "centos-stream:9"},
		{"centos", "centos-stream-10", "centos-stream:10"},
		{"centos", "centos-stream:10", "centos-stream:10"},
		{"CentOS", "centos-7", "7"},
	} {
		t.Run(tc.namespace+"/"+tc.distro, func(t *testing.T) {
			data := []byte(fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"bom-ref":"rpm","name":"example","version":"1","purl":"pkg:rpm/%s/example?distro=%s"}]}`, tc.namespace, tc.distro))
			redHatLoaders(t, data, func(t *testing.T, d Document) {
				if len(d.Subjects) != 1 || d.Subjects[0].Release != tc.wantRelease {
					t.Errorf("subjects=%+v, want release %q", d.Subjects, tc.wantRelease)
				}
				r, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{advisory("Red Hat:enterprise_linux:7::server", "example", "2"), advisory("Red Hat:enterprise_linux:9::baseos", "example", "2")}}, d.Subjects, Options{})
				if err != nil {
					t.Fatal(err)
				}
				if tc.wantRelease == "7" {
					if len(r.Findings) != 1 || len(r.Skipped) != 0 {
						t.Fatalf("report=%+v", r)
					}
				} else if len(r.Findings) != 0 || r.Skipped["centos-stream-unsupported"] != 1 {
					t.Fatalf("report=%+v", r)
				}
			})
		})
	}
}
