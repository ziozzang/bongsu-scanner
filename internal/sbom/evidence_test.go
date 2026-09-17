package sbom

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/scan"
)

func TestPackageEvidence(t *testing.T) {
	for _, evidence := range []string{"", "pom.properties", "manifest", "filename", "release-file", "package.json", "gemspec", "lockfile"} {
		t.Run(evidence, func(t *testing.T) {
			var p scan.Package
			b, _ := json.Marshal(map[string]string{"name": "lib", "version": "1", "type": "generic", "evidence": evidence})
			if err := json.Unmarshal(b, &p); err != nil {
				t.Fatal(err)
			}
			r := scan.Result{Name: "test", Packages: []scan.Package{p}}
			cdx, first := mustCDX(t, r)
			_, second := mustCDX(t, r)
			if !bytes.Equal(first, second) {
				t.Fatal("non-deterministic CycloneDX")
			}
			got, ok := property(cdx.Components[0], "bscan:evidence")
			if got != evidence || ok != (evidence != "") {
				t.Errorf("CycloneDX evidence = %q, present=%v", got, ok)
			}
			spdx, first := mustSPDX(t, r)
			_, second = mustSPDX(t, r)
			if !bytes.Equal(first, second) {
				t.Fatal("non-deterministic SPDX")
			}
			pkg, ok := findPackage(spdx, "lib")
			want := ""
			if evidence != "" {
				want = "bscan: evidence=" + evidence
			}
			if !ok || pkg.PackageComment != want {
				t.Errorf("SPDX comment = %q; want %q", pkg.PackageComment, want)
			}
		})
	}
}
