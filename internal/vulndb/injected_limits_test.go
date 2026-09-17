package vulndb

import (
	"archive/zip"
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestProductionResourceLimitDefaults(t *testing.T) {
	if osvMaxVersions != 5_000_000 || sqliteMaxRowBytes != 64<<20 || sqliteMaxExpandedBytes != 64<<20 {
		t.Fatalf("production limits changed: versions=%d row=%d expanded=%d", osvMaxVersions, sqliteMaxRowBytes, sqliteMaxExpandedBytes)
	}
}

func TestOSVInjectedVersionLimitBoundaries(t *testing.T) {
	testLimit(t, &osvMaxVersions, 4)
	for _, count := range []int{3, 4, 5} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			// Each affected entry is within the cap; their aggregate crosses it.
			entry := func(n int) string {
				return `{"package":{"ecosystem":"npm","name":"example"},"versions":[` + strings.Repeat(`"1",`, n-1) + `"2"]}`
			}
			body := `{"id":"OSV-boundary","affected":[` + entry(2) + `,` + entry(count-2) + `]}`
			data := fixtureZip(t, map[string]string{"record.json": body})
			zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
			if err != nil {
				t.Fatal(err)
			}
			record, err := decodeOSVMember(zr.File[0], SourceOSV)
			if count > osvMaxVersions {
				if err == nil || !strings.Contains(err.Error(), "exceeds 4 total versions") || record != nil {
					t.Fatalf("overflow: record=%+v err=%v", record, err)
				}
			} else if err != nil || record == nil || len(record.Affected) != 2 || len(record.Affected[0].Versions)+len(record.Affected[1].Versions) != count {
				t.Fatalf("boundary lost versions: record=%+v err=%v", record, err)
			}
		})
	}
}

func TestSQLiteInjectedExpansionLimitBoundaries(t *testing.T) {
	testLimit(t, &sqliteMaxExpandedBytes, int64(1024))
	decoder := new(sqliteReadDecoder)
	for _, size := range []int{1023, 1024, 1025, 1023} {
		raw := []byte(`{"id":"boundary"}`)
		raw = append(raw, bytes.Repeat([]byte(" "), size-len(raw))...)
		data, err := compressSQLiteJSON(raw)
		if err != nil {
			t.Fatal(err)
		}
		var record Record
		err = decoder.decode(data, &record)
		if int64(size) >= sqliteMaxExpandedBytes {
			if err == nil || !strings.Contains(err.Error(), "expanded size limit") {
				t.Fatalf("size=%d: overflow accepted: %v", size, err)
			}
		} else if err != nil || record.ID != "boundary" {
			t.Fatalf("size=%d: valid record rejected: %+v %v", size, record, err)
		}
	}
}
