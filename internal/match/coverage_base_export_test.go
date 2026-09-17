package match

import (
	"context"
	"strings"
	"testing"
)

func TestUbuntuCoverageRecommendsMaintainedExport(t *testing.T) {
	report, err := Run(context.Background(), &fakeStore{}, []Subject{{Ref: "a", Ecosystem: "Ubuntu", Release: "24.04", Name: "curl", Version: "1"}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.MissingCoverage) != 1 || !strings.HasSuffix(report.MissingCoverage[0], "bscan db update --add-ecosystem Ubuntu") {
		t.Fatalf("warning=%v", report.MissingCoverage)
	}
}
