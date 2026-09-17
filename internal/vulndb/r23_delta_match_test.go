package vulndb_test

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/match"
	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

type r23MatchStore struct{ record vulndb.Record }

func (s r23MatchStore) Lookup(string, string) ([]vulndb.Record, error) {
	return []vulndb.Record{s.record}, nil
}
func (s r23MatchStore) Ecosystems() ([]string, error) { return []string{"Debian:12"}, nil }
func (s r23MatchStore) Meta() (vulndb.Meta, error)    { return vulndb.Meta{}, nil }
func (s r23MatchStore) Close() error                  { return nil }

func TestR22WithdrawalSuppressesOtherSource(t *testing.T) {
	for _, source := range []string{vulndb.SourceDebian, vulndb.SourceNVD, vulndb.SourceGHSA, vulndb.SourceOSV} {
		for _, reverse := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%t", source, reverse), func(t *testing.T) {
				active := vulndb.Record{ID: "CVE-2026-1001", Source: source, Affected: []vulndb.Affected{{Ecosystem: "Debian:12", Package: "demo", Ranges: []vulndb.Range{{Type: "ECOSYSTEM", Events: []vulndb.Event{{Introduced: "0"}, {Fixed: "2"}}}}}}}
				active.Provenance = []vulndb.RecordSource{{Name: source, URL: "https://example.test/active"}}
				active.Database = map[string]any{"severity": "HIGH", "origin": source}
				want := active
				dead := vulndb.Record{ID: active.ID, Source: vulndb.SourceRedHatVEX, Withdrawn: "2026-09-15T00:00:00Z", Modified: "2026-09-15T00:00:00Z"}
				subjects := []match.Subject{{Ecosystem: "Debian", Release: "12", Name: "demo", Version: "1"}}
				before, err := match.Run(context.Background(), r23MatchStore{active}, subjects, match.Options{})
				if err != nil || len(before.Findings) != 1 {
					t.Fatalf("baseline: %+v %v", before, err)
				}
				if reverse {
					active, dead = dead, active
				}
				vulndb.Merge(&active, &dead)
				if !reflect.DeepEqual(active, want) {
					t.Fatalf("other contribution changed: %+v", active)
				}
				after, err := match.Run(context.Background(), r23MatchStore{active}, subjects, match.Options{})
				if err != nil || len(after.Findings) != 1 || after.Skipped["withdrawn"] != 0 {
					t.Fatalf("finding suppressed: %+v %v", after, err)
				}
			})
		}
	}
}
