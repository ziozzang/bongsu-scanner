package match

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

func TestRedHatHostAndImageMatching(t *testing.T) {
	for _, tc := range []struct {
		ns, os, ver, distro, eco, fixed, wantRelease, skip string
		want                                               int
	}{
		{"rhel", "rhel", "9.4", "rhel-9.4", "Red Hat:enterprise_linux:9::appstream", "1:1.2-4.el9", "9", "", 1},
		{"redhat", "rhel", "9.4", "", "Red Hat:enterprise_linux:9::baseos", "1:1.2-4.el9", "9", "", 1},
		{"rhel", "rhel", "9", "", "Red Hat:enterprise_linux:9::baseos", "1:1.2-4.el9", "9", "", 1},
		{"rhel", "rhel", "10.2", "rhel-10.2", "Red Hat:enterprise_linux:10.0", "1:1.2-4.el9", "10.2", "release-not-in-database", 0},
		{"rhel", "rhel", "9.4", "rhel-9.4", "Red Hat:enterprise_linux:9::baseos", "1:1.2-3.el9", "9", "", 0},
		{"rhel", "rhel", "9.4", "rhel-9.4", "Red Hat:enterprise_linux:8::baseos", "1:1.2-4.el9", "9", "release-not-in-database", 0},
		{"centos", "centos", "7", "", "Red Hat:enterprise_linux:7::server", "1:1.2-4.el9", "7", "", 1},
		{"centos", "centos", "9", "", "Red Hat:enterprise_linux:9::baseos", "1:1.2-4.el9", "centos-stream:9", "centos-stream-unsupported", 0},
		{"centos", "centos", "9", "9", "Red Hat:enterprise_linux:9::baseos", "1:1.2-4.el9", "centos-stream:9", "centos-stream-unsupported", 0},
		{"centos", "centos", "8", "centos-8", "Red Hat:enterprise_linux:8::baseos", "1:1.2-4.el9", "centos-stream:8", "centos-stream-unsupported", 0},
		{"centos", "centos", "10", "centos-10", "Red Hat:enterprise_linux:10.2", "1:1.2-4.el9", "centos-stream:10", "centos-stream-unsupported", 0},
	} {
		t.Run(tc.ns+tc.ver+tc.distro+tc.eco+tc.fixed, func(t *testing.T) {
			data := []byte(fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"operating-system","name":%q,"version":%q},{"bom-ref":"rpm","type":"library","name":"example-libs","purl":"pkg:rpm/%s/example-libs@1.2-3.el9?epoch=1&upstream=example&distro=%s"}]}`, tc.os, tc.ver, tc.ns, tc.distro))
			path := filepath.Join(t.TempDir(), "bom.json")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			for _, loader := range []func() (Document, error){func() (Document, error) { return Load(data) }, func() (Document, error) { return LoadFile(path) }} {
				d, err := loader()
				if err != nil {
					t.Fatal(err)
				}
				if len(d.Subjects) != 1 || d.Subjects[0].Release != tc.wantRelease {
					t.Fatalf("subjects=%+v", d.Subjects)
				}
				rec := advisory(tc.eco, "example", tc.fixed)
				// Lifecycle errata and other products must not contaminate mainline matches.
				for _, eco := range []string{"Red Hat:rhel_eus:9.4::appstream", "Red Hat:rhel_e4s:9.4::baseos", "Red Hat:openshift:9"} {
					rec.Affected = append(rec.Affected, advisory(eco, "example", "9:99-99.el9_4").Affected...)
				}
				report, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{rec}}, d.Subjects, Options{})
				if err != nil || len(report.Findings) != tc.want || (tc.skip != "" && report.Skipped[tc.skip] != 1) {
					t.Fatalf("report=%+v err=%v", report, err)
				}
			}
		})
	}
}

func TestCentOSStreamSkipWithoutCoverage(t *testing.T) {
	if got := subjectSkip(Subject{Ecosystem: "Red Hat", Release: "centos-stream:9"}, nil); got != "centos-stream-unsupported" {
		t.Fatalf("skip=%q", got)
	}
}

func TestCoverageWarningExportNames(t *testing.T) {
	subjects := []Subject{{Ref: "r", Ecosystem: "Red Hat", Release: "9", Version: "1"}, {Ref: "a", Ecosystem: "Alpine", Release: "v3.20", Version: "1"}, {Ref: "u", Ecosystem: "Ubuntu", Release: "22.04", Version: "1"}}
	report, err := Run(context.Background(), &fakeStore{}, subjects, Options{})
	want := []string{"coverage gap: Alpine:v3.20 (1 subjects) — run bscan db update --add-ecosystem Alpine", "coverage gap: Red Hat:9 (1 subjects) — run bscan db update --add-ecosystem 'Red Hat'", "coverage gap: Ubuntu:22.04 (1 subjects) — run bscan db update --add-ecosystem 'Ubuntu:22.04:LTS'"}
	if err != nil || !reflect.DeepEqual(report.MissingCoverage, want) {
		t.Fatalf("warnings=%v error=%v", report.MissingCoverage, err)
	}
}

func TestRPMVersionFromPURLPreservesEpoch(t *testing.T) {
	for _, tc := range []struct{ version, purlVersion, epoch, want string }{
		{"", "1.2-3.el9", "1", "1:1.2-3.el9"},
		{"", "1.2-3.el9", "0", "0:1.2-3.el9"},
		{"", "1.2-3.el9", "", "1.2-3.el9"},
		{"", "1.2-3.el9", "bad", "1.2-3.el9"},
		{"", "1:1.2-3.el9", "1", "1:1.2-3.el9"},
		{"2:1.2-3.el9", "1.2-3.el9", "1", "2:1.2-3.el9"},
		{"", "", "1", ""},
	} {
		data := []byte(fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"bom-ref":"rpm","name":"example","version":%q,"purl":"pkg:rpm/rhel/example%s?epoch=%s&distro=rhel-9"}]}`, tc.version, func() string {
			if tc.purlVersion != "" {
				return "@" + tc.purlVersion
			}
			return ""
		}(), tc.epoch))
		path := filepath.Join(t.TempDir(), "bom.json")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		for _, loader := range []func() (Document, error){func() (Document, error) { return Load(data) }, func() (Document, error) { return LoadFile(path) }} {
			d, err := loader()
			if err != nil {
				t.Fatal(err)
			}
			if len(d.Subjects) != 1 || d.Subjects[0].Version != tc.want {
				t.Fatalf("%+v: subjects=%+v", tc, d.Subjects)
			}
		}
	}
}
