package vulndb

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestUbuntuRealOSVCatalog optionally ingests saved /v1/query responses through
// the production converter and catalog builder. Set BONGSU_TEST_UBUNTU_OSV to a
// JSON {"vulns":[...]} containing about 20 real Ubuntu advisories; optionally set
// BONGSU_TEST_UBUNTU_DB to an empty destination for a subsequent CLI match.
// Keeping networking outside the test makes ordinary regression runs offline.
func TestUbuntuRealOSVCatalog(t *testing.T) {
	input := os.Getenv("BONGSU_TEST_UBUNTU_OSV")
	if input == "" {
		t.Skip("set BONGSU_TEST_UBUNTU_OSV to saved OSV query records")
	}
	b, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		Vulns []osvVuln `json:"vulns"`
	}
	if err := json.Unmarshal(b, &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Vulns) < 20 || len(response.Vulns) > 30 {
		t.Fatalf("expected 20–30 real records, got %d", len(response.Vulns))
	}
	records := make(map[string]*Record)
	packages := make(map[string]bool)
	for i := range response.Vulns {
		v := &response.Vulns[i]
		record, ok := ConvertOSV(v, SourceOSV)
		if !ok {
			t.Fatalf("conversion rejected %s", v.ID)
		}
		record.Provenance = []RecordSource{{Name: SourceOSV, URL: "https://api.osv.dev/v1/vulns/" + v.ID}}
		for _, a := range record.Affected {
			if a.Ecosystem == "Ubuntu:24.04:LTS" {
				packages[a.Package] = true
				if EcosystemRelease(a.Ecosystem) != "24.04" {
					t.Fatalf("%s: unnormalized Noble release", v.ID)
				}
			}
		}
		records[record.ID] = record
	}
	for _, name := range []string{"openssl", "curl", "libxml2", "glibc"} {
		if !packages[name] {
			t.Fatalf("no Noble affected entries for %s", name)
		}
	}
	dir := os.Getenv("BONGSU_TEST_UBUNTU_DB")
	if dir == "" {
		dir = t.TempDir()
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	meta := Meta{SchemaVersion: SchemaVersion, UpdatedAt: time.Now().UTC()}
	if err := buildIndexes(dir, records, &meta); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(dir, "meta.json"), meta); err != nil {
		t.Fatal(err)
	}
	if err := writeManifest(dir, Options{}); err != nil {
		t.Fatal(err)
	}
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for name := range packages {
		got, err := store.Lookup("Ubuntu", name)
		if err != nil || len(got) == 0 {
			t.Fatalf("indexed lookup %s: records=%d, error=%v", name, len(got), err)
		}
		for _, record := range got {
			original := records[record.ID]
			if original == nil || len(original.Affected) != len(record.Affected) {
				t.Fatalf("lost affected entries for %s", record.ID)
			}
			ecosystems := make(map[string]int)
			for _, a := range original.Affected {
				ecosystems[a.Ecosystem]++
			}
			for _, a := range record.Affected {
				if ecosystems[a.Ecosystem] == 0 {
					t.Fatalf("original ecosystem lost: %s", a.Ecosystem)
				}
				ecosystems[a.Ecosystem]--
			}
		}
	}
	t.Logf("converted and indexed %d real Ubuntu advisories at %s", len(records), dir)
}
