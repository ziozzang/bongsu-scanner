package match

import (
	"context"
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

func TestRedHatVEXStatuses(t *testing.T) {
	for _, status := range []string{"affected", "will-not-fix", "fix-deferred", "out-of-support-scope", "under-investigation", "not-affected"} {
		t.Run(status, func(t *testing.T) {
			r := advisory("Red Hat:enterprise_linux:9", "openssl", "")
			r.ID = "CVE-2025-12345"
			r.Source = vulndb.SourceRedHatVEX
			r.Affected[0].Ranges = []vulndb.Range{{Type: "ECOSYSTEM", Events: []vulndb.Event{{Introduced: "0"}}}}
			r.Affected[0].Database = map[string]any{"redhat_status": status}
			if status == "not-affected" {
				r.Affected[0].Ranges = nil
			}
			subject := Subject{Ref: "rpm", Type: "rpm", Ecosystem: "Red Hat", Release: "9", Name: "openssl", Version: "1:3.0.7-27.el9"}
			report, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{r}}, []Subject{subject}, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if status == "not-affected" {
				if len(report.Findings) != 0 {
					t.Fatalf("marker matched: %+v", report)
				}
				return
			}
			if len(report.Findings) != 1 {
				t.Fatalf("%+v", report)
			}
			f := report.Findings[0]
			confidence := "low"
			if status == "affected" {
				confidence = "high"
			}
			if f.DistroStatus != status || len(f.FixedIn) != 0 || f.Confidence != confidence {
				t.Fatalf("%+v", f)
			}
			report, err = Run(context.Background(), &fakeStore{records: []vulndb.Record{r}}, []Subject{subject}, Options{OnlyFixed: true})
			if err != nil || len(report.Findings) != 0 {
				t.Fatalf("only fixed: %+v %v", report, err)
			}
		})
	}
}
func TestRedHatVEXNotAffectedSuppressesExactRelease(t *testing.T) {
	for _, release := range []string{"9", "8", "rhel_eus:9.4"} {
		r := advisory("Red Hat:enterprise_linux:9", "openssl", "1:3.5.1-7.el9")
		r.ID = "CVE-2025-11187"
		marker := vulndb.Record{ID: "VEX-2025-11187", Aliases: []string{r.ID}, Affected: []vulndb.Affected{{Ecosystem: "Red Hat:" + release, Package: "openssl", Database: map[string]any{"redhat_status": "not-affected"}}}}
		subjects := []Subject{{Ref: "r", Type: "rpm", Ecosystem: "Red Hat", Release: "9", Name: "openssl", Version: "1:3.0.7-27.el9"}}
		report, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{r, marker}}, subjects, Options{})
		want := 1
		if release == "9" {
			want = 0
		}
		if err != nil || len(report.Findings) != want {
			t.Fatalf("release=%s report=%+v err=%v", release, report, err)
		}
	}
}
func TestRedHatVEXVendorSeverity(t *testing.T) {
	r := advisory("Red Hat:enterprise_linux:9", "openssl", "1:3.5.1-7.el9")
	r.ID = "CVE-2025-12345"
	r.Database = map[string]any{"severity": "Important"}
	r.Severity = []vulndb.Severity{{Type: "CVSS_V3", Score: "9.8"}}
	subjects := []Subject{{Ref: "r", Type: "rpm", Ecosystem: "Red Hat", Release: "9", Name: "openssl", Version: "1:3.0.7-27.el9"}}
	for _, local := range []string{"", "Low"} {
		r.Affected[0].Database = map[string]any{"severity": local}
		for _, policy := range []string{"distro", "cvss", "max"} {
			report, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{r}}, subjects, Options{SeveritySource: policy})
			if err != nil || len(report.Findings) != 1 {
				t.Fatalf("%+v %v", report, err)
			}
			want := "CRITICAL"
			if policy == "distro" {
				want = "HIGH"
				if local != "" {
					want = "LOW"
				}
			}
			if report.Findings[0].Severity != want || report.Findings[0].Score != 9.8 {
				t.Fatalf("local=%s policy=%s finding=%+v", local, policy, report.Findings[0])
			}
		}
	}
}
func TestRedHatVEXModuleMetadata(t *testing.T) {
	for _, label := range []string{"", "python39:3.9:123:abcd"} {
		r := advisory("Red Hat:enterprise_linux:8::appstream", "python39", "")
		r.Affected[0].Ranges = []vulndb.Range{{Type: "ECOSYSTEM", Events: []vulndb.Event{{Introduced: "0"}}}}
		r.Affected[0].Database = map[string]any{"modularity": "python39:3.9", "redhat_status": "affected"}
		subjects := []Subject{{Ref: "r", Type: "rpm", Ecosystem: "Red Hat", Release: "8", Name: "python39", Version: "3.9.1-1.el8", Modularity: label}}
		report, err := Run(context.Background(), &fakeStore{records: []vulndb.Record{r}}, subjects, Options{})
		want := 0
		if label != "" {
			want = 1
		}
		if err != nil || len(report.Findings) != want {
			t.Fatalf("label=%s report=%+v err=%v", label, report, err)
		}
	}
}
func TestRedHatVEXMergeStatus(t *testing.T) {
	for _, status := range []string{"affected", "will-not-fix", "fix-deferred", "under-investigation", "out-of-support-scope"} {
		for _, reverse := range []bool{false, true} {
			a := Finding{Confidence: "high"}
			b := Finding{DistroStatus: status, Confidence: "low"}
			if reverse {
				a, b = b, a
			}
			mergeFinding(&a, b)
			if a.DistroStatus != status || status != "affected" && a.Confidence != "low" {
				t.Fatalf("status=%s reverse=%t finding=%+v", status, reverse, a)
			}
		}
	}
}
