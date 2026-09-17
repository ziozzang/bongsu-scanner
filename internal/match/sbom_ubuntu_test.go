package match

import (
	"context"
	"fmt"
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

func TestUbuntuRelease(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"ubuntu-24.04", "24.04"}, {"24.04", "24.04"},
		{"Ubuntu:24.04:LTS", "24.04"}, {"Ubuntu:Pro:24.04:LTS", "24.04"},
		{"24.04:LTS", "24.04"}, {"Pro:18.04:LTS", "18.04"},
		{"noble", "24.04"}, {"jammy", "22.04"}, {"focal", "20.04"},
		{"bionic", "18.04"}, {"plucky", "25.04"}, {"questing", "25.10"},
		{"resolute", "26.04"}, {"ubuntu-resolute", "26.04"},
		{"", ""}, {"future", "future"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			if got := release("Ubuntu", tc.input); got != tc.want {
				t.Fatalf("release=%q, want %q", got, tc.want)
			}
		})
	}
}

func TestUbuntuMatchReleaseBoundary(t *testing.T) {
	for _, ecosystem := range []string{"Ubuntu:24.04:LTS", "Ubuntu:Pro:24.04:LTS"} {
		for _, tc := range []struct {
			distro, version string
			want            int
		}{
			{"ubuntu-24.04", "3.0.13-0ubuntu3", 1},
			{"ubuntu-22.04", "3.0.13-0ubuntu3", 0},
			{"noble", "3.0.13-0ubuntu3", 1},
			{"ubuntu-24.04", "3.0.13-0ubuntu3.1", 0},
		} {
			t.Run(ecosystem+"/"+tc.distro+"/"+tc.version, func(t *testing.T) {
				raw := fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"bom-ref":"openssl","type":"library","name":"openssl","version":%q,"purl":"pkg:deb/ubuntu/openssl@%s?distro=%s"}]}`, tc.version, tc.version, tc.distro)
				doc, err := Load([]byte(raw))
				if err != nil {
					t.Fatal(err)
				}
				store := &fakeStore{records: []vulndb.Record{advisory(ecosystem, "openssl", "3.0.13-0ubuntu3.1")}}
				result, err := Run(context.Background(), store, doc.Subjects, Options{Details: true})
				if err != nil || len(result.Findings) != tc.want {
					t.Fatalf("findings=%+v skipped=%v error=%v", result.Findings, result.Skipped, err)
				}
				if tc.want > 0 && result.Findings[0].Affected.Ecosystem != ecosystem {
					t.Fatal("original ecosystem was lost")
				}
			})
		}
	}
}

func TestUbuntuHostReleaseWithoutDistro(t *testing.T) {
	for _, tc := range []struct{ version, codename, want string }{
		{"24.04", "noble", "24.04"}, {"", "resolute", "26.04"},
	} {
		raw := fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"application","properties":[{"name":"bscan:host:operating-system","value":"ubuntu"},{"name":"bscan:host:os-version","value":%q},{"name":"bscan:os:codename","value":%q}]}},"components":[{"type":"library","name":"openssl","version":"3.0.13-0ubuntu3","purl":"pkg:deb/ubuntu/openssl@3.0.13-0ubuntu3"}]}`, tc.version, tc.codename)
		doc, err := Load([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		if doc.Subjects[0].Release != tc.want {
			t.Fatalf("subject=%+v, want release %s", doc.Subjects[0], tc.want)
		}
	}
}
