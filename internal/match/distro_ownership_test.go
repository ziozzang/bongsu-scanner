package match

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ziozzang/bongsu-scanner/internal/sbom"
	"github.com/ziozzang/bongsu-scanner/internal/scan"
	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
	"os"
	"path/filepath"
	"testing"
)

func TestDistroModuleBoundary(t *testing.T) {
	for _, modular := range []bool{false, true} {
		for _, label := range []string{"", "python38:3.8:123:abcd"} {
			fixed := "0:3.0.4-19.el8"
			if modular {
				fixed = "0:3.0.4-19.module+el8.5.0+12211+8f7c9a4f"
			}
			data := []byte(fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"bom-ref":"rpm","name":"python3-chardet","version":"3.0.4-7.el8","purl":"pkg:rpm/redhat/python3-chardet@3.0.4-7.el8?distro=rhel-8.10","properties":[{"name":"bscan:modularity","value":%q}]}]}`, label))
			for _, stream := range []bool{false, true} {
				d, e := Load(data)
				if stream {
					p := filepath.Join(t.TempDir(), "bom.json")
					if err := os.WriteFile(p, data, 0600); err != nil {
						t.Fatal(err)
					}
					d, e = LoadFile(p)
				}
				if e != nil {
					t.Fatal(e)
				}
				r, e := Run(context.Background(), &fakeStore{records: []vulndb.Record{advisory("Red Hat:8", "python3-chardet", fixed)}}, d.Subjects, Options{})
				want := 0
				if modular == (label != "") {
					want = 1
				}
				if e != nil || len(r.Findings) != want {
					t.Fatalf("modular=%t label=%q stream=%t findings=%d skipped=%v err=%v", modular, label, stream, len(r.Findings), r.Skipped, e)
				}
				if want == 0 && r.Skipped["module-mismatch"] != 1 {
					t.Fatalf("counter: %v", r.Skipped)
				}
			}
		}
	}
}
func TestDistroOwnedLanguageSkip(t *testing.T) {
	d, e := Load([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"bom-ref":"py","name":"idna","version":"2.5","purl":"pkg:pypi/idna@2.5","properties":[{"name":"bscan:owner","value":"rpm:python3-idna@2.5-8.el8_10"}]},{"bom-ref":"rpm","name":"python3-idna","version":"2.5-8.el8_10","purl":"pkg:rpm/redhat/python3-idna@2.5-8.el8_10?distro=rhel-8.10"}]}`))
	if e != nil {
		t.Fatal(e)
	}
	r, e := Run(context.Background(), &fakeStore{records: []vulndb.Record{advisory("PyPI", "idna", "3.7"), advisory("Red Hat:8", "python3-idna", "2.5-99.el8")}}, d.Subjects, Options{})
	if e != nil || len(r.Findings) != 1 || r.Findings[0].Subject.Type != "rpm" || r.Skipped["distro-owned"] != 1 {
		t.Fatalf("report=%+v err=%v", r, e)
	}
}

func TestDistroPropertyRoundTrip(t *testing.T) {
	for _, format := range []string{"cyclonedx", "spdx"} {
		var p scan.Package
		if err := json.Unmarshal([]byte(`{"name":"idna","version":"2.5","type":"pypi","purl":"pkg:pypi/idna@2.5","owner":"rpm:python3-idna@2.5-8.el8_10","modularity":"python38:3.8:123:abcd"}`), &p); err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(t.TempDir(), "bom.json")
		if err := sbom.Write(file, format, scan.Result{Name: "test", Packages: []scan.Package{p}}); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, stream := range []bool{false, true} {
			d, err := Load(data)
			if stream {
				d, err = LoadFile(file)
			}
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, s := range d.Subjects {
				if s.Type != "pypi" {
					continue
				}
				found = true
				wire, err := json.Marshal(s)
				if err != nil {
					t.Fatal(err)
				}
				var fields map[string]any
				if err = json.Unmarshal(wire, &fields); err != nil {
					t.Fatal(err)
				}
				if fields["owner"] != "rpm:python3-idna@2.5-8.el8_10" || fields["modularity"] != "python38:3.8:123:abcd" {
					t.Fatalf("%s stream=%t: %s", format, stream, wire)
				}
				r, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{advisory("PyPI", "idna", "3.7")}}, []Subject{s}, Options{})
				if err != nil || len(r.Findings) != 0 || r.Skipped["distro-owned"] != 1 {
					t.Fatalf("%s stream=%t: %+v %v", format, stream, r, err)
				}
			}
			if !found {
				t.Fatal("subject lost")
			}
		}
	}
}

func TestDistroModuleEventsSharedCache(t *testing.T) {
	for _, kind := range []string{"fixed", "last_affected", "introduced", "versions"} {
		rec := advisory("Red Hat:8", "python3-chardet", "99-1.el8")
		modular := "3.0.4-19.module+el8.5.0+12211+8f7c9a4f"
		a := &rec.Affected[0]
		switch kind {
		case "fixed":
			a.Ranges[0].Events[1] = vulndb.Event{Fixed: modular}
		case "last_affected":
			a.Ranges[0].Events[1] = vulndb.Event{LastAffected: modular}
		case "introduced":
			a.Ranges[0].Events[0] = vulndb.Event{Introduced: "1-1.module+el8"}
		case "versions":
			a.Ranges = nil
			a.Versions = []string{modular}
		}
		subjects := []Subject{{Ref: "plain", Name: "python3-chardet", Type: "rpm", Ecosystem: "Red Hat", Release: "8", Version: modular}, {Ref: "mod", Name: "python3-chardet", Type: "rpm", Ecosystem: "Red Hat", Release: "8", Version: modular, Modularity: "python38:3.8:123:abcd"}}
		if kind == "fixed" {
			subjects[0].Version = "3.0.4-7.el8"
			subjects[1].Version = subjects[0].Version
		}
		r, e := Run(context.Background(), &fakeStore{records: []vulndb.Record{rec}}, subjects, Options{})
		if e != nil || len(r.Findings) != 1 || r.Findings[0].Subject.Ref != "mod" || r.Skipped["module-mismatch"] != 1 {
			t.Fatalf("%s: %+v %v", kind, r, e)
		}
	}
}
