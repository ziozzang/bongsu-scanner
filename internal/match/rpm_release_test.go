package match

import (
	"context"
	"fmt"
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

func TestRPMOSVRelease(t *testing.T) {
	for _, tc := range []struct{ eco, distro, want string }{
		{"Rocky Linux", "rocky-9.4", "9"}, {"Rocky Linux", "rocky-linux-8.10", "8"},
		{"AlmaLinux", "almalinux-9.5", "9"}, {"AlmaLinux", "10.0", "10"},
		{"openSUSE", "opensuse-leap-15.6", "Leap 15.6"}, {"openSUSE", "opensuse-tumbleweed-20260901", "Tumbleweed"},
		{"SUSE", "sles-15.6", "Linux Enterprise Server 15 SP6"},
		{"Red Hat", "rhel-9.4", "9"},
		{"Red Hat", "redhat-9.4", "9"}, {"Red Hat", "rhel-9", "9"},
		{"Red Hat", "9.4", "9"}, {"Red Hat", "10.2", "10"},
		{"Red Hat", "centos-7.9", "7"}, {"Red Hat", "centos-6", "6"},
		{"Red Hat", "centos-8", "centos-stream:8"}, {"Red Hat", "centos-9", "centos-stream:9"}, {"Red Hat", "centos-10", "centos-stream:10"},
		{"Red Hat", "rhel-unknown", ""},
		{"Red Hat", "Red Hat:enterprise_linux:9::baseos", "9"},
		{"SUSE", "SUSE:Linux Enterprise Server 15 SP6-LTSS", "Linux Enterprise Server 15 SP6-LTSS"},
		{"Rocky Linux", "rocky-unknown", ""}, {"Rocky Linux", "almalinux-9.4", ""},
	} {
		if got := release(tc.eco, tc.distro); got != tc.want {
			t.Errorf("%s %s: %q != %q", tc.eco, tc.distro, got, tc.want)
		}
	}
}

func TestRPMMatchReleaseBoundary(t *testing.T) {
	for _, tc := range []struct {
		distro, version string
		want            int
	}{
		{"rocky-9.4", "1:1.2-3.el9", 1},
		{"rocky-8.10", "1:1.2-3.el9", 0},
		{"rocky-9.4", "1:1.2-4.el9", 0},
	} {
		t.Run(tc.distro+tc.version, func(t *testing.T) {
			data := fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"bom-ref":"rpm","type":"library","name":"example-libs","version":%q,"purl":"pkg:rpm/rocky/example-libs@1.2-3.el9?arch=x86_64&distro=%s&epoch=1&upstream=example"}]}`, tc.version, tc.distro)
			doc, err := Load([]byte(data))
			if err != nil {
				t.Fatal(err)
			}
			store := &fakeStore{records: []vulndb.Record{advisory("Rocky Linux:9", "example", "1:1.2-4.el9")}}
			r, err := Run(context.Background(), store, doc.Subjects, Options{})
			if err != nil || len(r.Findings) != tc.want {
				t.Fatalf("findings=%+v skipped=%v error=%v", r.Findings, r.Skipped, err)
			}
		})
	}
}
