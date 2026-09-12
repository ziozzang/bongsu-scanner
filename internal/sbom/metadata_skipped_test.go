package sbom

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/scan"
)

func TestMetadataSkippedInBothFormats(t *testing.T) {
	for _, count := range []int{0, 1, 42} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			r := fixture()
			r.Scan = &scan.ScanMetadata{Partial: count > 0, MetadataSkipped: count}
			cdx, cdxBytes := mustCDX(t, r)
			value, present := property(cdx.Metadata.Component, "bscan:scan:metadata-skipped")
			if present != (count > 0) || (present && value != strconv.Itoa(count)) {
				t.Errorf("CycloneDX metadata-skipped = %q, present = %t, count = %d", value, present, count)
			}
			if value, _ := property(cdx.Metadata.Component, "bscan:scan:partial"); value != strconv.FormatBool(count > 0) {
				t.Errorf("CycloneDX partial = %q", value)
			}
			if _, present := property(cdx.Metadata.Component, "bscan:scan:skipped-errors"); present {
				t.Error("metadata skips must not be reported as skipped errors")
			}

			spdx, spdxBytes := mustSPDX(t, r)
			found := false
			for _, annotation := range spdx.Packages[0].Annotations {
				const prefix = "bscan scan metadata: "
				if !strings.HasPrefix(annotation.Comment, prefix) {
					continue
				}
				found = true
				var metadata map[string]json.RawMessage
				if err := json.Unmarshal([]byte(strings.TrimPrefix(annotation.Comment, prefix)), &metadata); err != nil {
					t.Fatal(err)
				}
				value, present := metadata["metadata_skipped"]
				if present != (count > 0) || (present && string(value) != strconv.Itoa(count)) {
					t.Errorf("SPDX metadata_skipped = %s, present = %t, count = %d", value, present, count)
				}
				if string(metadata["partial"]) != strconv.FormatBool(count > 0) {
					t.Errorf("SPDX partial = %s", metadata["partial"])
				}
				if _, present := metadata["skipped_errors"]; present {
					t.Error("metadata skips must not be reported as skipped errors")
				}
			}
			if !found {
				t.Error("SPDX scan annotation missing")
			}
			_, nextCDX := mustCDX(t, r)
			_, nextSPDX := mustSPDX(t, r)
			if !bytes.Equal(cdxBytes, nextCDX) || !bytes.Equal(spdxBytes, nextSPDX) {
				t.Error("metadata output differs between repeated writes")
			}
		})
	}
}

func TestWritersShareStableDocumentIdentity(t *testing.T) {
	for _, withPackages := range []bool{false, true} {
		t.Run(strconv.FormatBool(withPackages), func(t *testing.T) {
			r := fixture() // Includes duplicate purls and a package without a purl.
			if !withPackages {
				r.Packages = nil
			}
			cdx, _ := mustCDX(t, r)
			spdx, _ := mustSPDX(t, r)
			const prefix = "https://bongsu.local/spdx/"
			hash := strings.TrimPrefix(spdx.DocumentNamespace, prefix)
			if !strings.HasPrefix(spdx.DocumentNamespace, prefix) || !hexDigest.MatchString(hash) {
				t.Fatalf("invalid SPDX namespace: %q", spdx.DocumentNamespace)
			}
			if cdx.Serial != "urn:uuid:"+uuidFromHash(hash) || cdx.Metadata.Component.BOMRef != "root-"+hash[:16] {
				t.Error("writers did not derive document identifiers from the same hash")
			}
			// Reverse writer order to catch mutation of the shared Result.
			nextSPDX, _ := mustSPDX(t, r)
			nextCDX, _ := mustCDX(t, r)
			if cdx.Serial != nextCDX.Serial || cdx.Metadata.Component.BOMRef != nextCDX.Metadata.Component.BOMRef || spdx.DocumentNamespace != nextSPDX.DocumentNamespace {
				t.Error("identifiers changed for the same Result")
			}
		})
	}
}
