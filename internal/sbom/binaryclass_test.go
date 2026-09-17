package sbom

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/scan"
)

func TestClassifiedBinarySBOMIdentifiers(t *testing.T) {
	root := t.TempDir()
	// Each fixture carries the version string plus the product-specific
	// secondary marker the classifier requires (see internal/scan/binaryclass.go).
	fixtures := []struct{ file, signature, name, version, vendorProduct string }{
		{"python3", "Python 3.12.14\x00Py_InitializeEx", "python", "3.12.14", "python:python"},
		{"node", "node/v22.12.0\x00node_module_register", "node", "22.12.0", "nodejs:node.js"},
		{"ruby", "ruby 3.3.5p100\x00ruby_init", "ruby", "3.3.5", "ruby-lang:ruby"},
		{"openssl", "OpenSSL 3.0.13 30 Jan 2024\x00OPENSSLDIR", "openssl", "3.0.13", "openssl:openssl"},
		{"busybox", "BusyBox v1.36.1\x00BusyBox multi-call", "busybox", "1.36.1", "busybox:busybox"},
		{"nginx", "nginx/1.27.0\x00ngx_http", "nginx", "1.27.0", "f5:nginx"},
		{"httpd", "Apache/2.4.62\x00ap_server_root", "httpd", "2.4.62", "apache:http_server"},
		{"redis-server", "redis_version:7.2.4\x00redis-server", "redis", "7.2.4", "redis:redis"},
		{"postgres", "PostgreSQL 16.4\x00PGDATA", "postgres", "16.4", "postgresql:postgresql"},
		{"curl", "curl 8.9.1\x00curl_easy_init", "curl", "8.9.1", "haxx:curl"},
	}
	for _, f := range fixtures {
		if err := os.WriteFile(filepath.Join(root, f.file), []byte("\x7fELF\x00"+f.signature+"\x00"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	r, err := scan.DirectoryContext(context.Background(), root, "binaries", scan.Options{})
	if err != nil {
		t.Fatal(err)
	}
	cdx, _ := mustCDX(t, r)
	spdx, _ := mustSPDX(t, r)
	if len(cdx.Components) != len(fixtures) {
		t.Fatalf("got %d components, want %d", len(cdx.Components), len(fixtures))
	}
	for _, f := range fixtures {
		purl := "pkg:generic/" + f.name + "@" + f.version
		cpe := "cpe:2.3:a:" + f.vendorProduct + ":" + f.version + ":*:*:*:*:*:*:*"
		found := false
		for _, c := range cdx.Components {
			if c.PURL != purl {
				continue
			}
			found = true
			if c.CPE != cpe {
				t.Errorf("%s: cpe=%s", purl, c.CPE)
			}
			if evidence, _ := property(c, "bscan:evidence"); evidence != "binary" {
				t.Errorf("%s: evidence=%s", purl, evidence)
			}
		}
		if !found {
			t.Errorf("missing CycloneDX %s", purl)
		}
		p, ok := findPackage(spdx, f.name)
		if !ok || !strings.Contains(p.PackageComment, "evidence=binary") {
			t.Errorf("missing SPDX evidence for %s", f.name)
		}
		refs := map[string]bool{}
		for _, ref := range p.ExternalRefs {
			refs[ref.ReferenceLocator] = true
		}
		if !refs[purl] || !refs[cpe] {
			t.Errorf("SPDX %s references=%v", f.name, refs)
		}
	}
}
