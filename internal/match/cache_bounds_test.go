package match

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

func TestLookupCacheLRUEvictionAndOversize(t *testing.T) {
	c := newLookupCache[string](500)
	c.put("a", "first", 100)
	c.put("b", "second", 100)
	if value, ok := c.get("a"); !ok || value != "first" {
		t.Fatal("cache miss")
	}
	c.put("c", "third", 100)
	if _, ok := c.get("b"); ok {
		t.Fatal("least recently used entry remained resident")
	}
	if _, ok := c.get("a"); !ok {
		t.Fatal("recent entry was evicted")
	}
	c.put("oversize", "large", 501)
	if _, ok := c.get("oversize"); ok || c.bytes > c.limit {
		t.Fatal("oversized entry was cached")
	}
	c.put("a", "replacement", 100)
	if value, ok := c.get("a"); !ok || value != "replacement" {
		t.Fatal("replacement failed")
	}
	c.remove("a")
	c.remove("c")
	if c.bytes != 0 || c.lru.Len() != 0 || len(c.entries) != 0 {
		t.Fatal("eviction leaked accounting or references")
	}
}

func TestCacheCostRejectsCyclicValues(t *testing.T) {
	value := map[string]any{}
	value["self"] = value
	if jsonValueBytes(value) <= 32<<20 {
		t.Fatal("cyclic data would fit in cache")
	}
}

func TestVersionAndSeverityCacheEvictionPreservesResults(t *testing.T) {
	c := newVersionCache()
	for i := 0; i < 30000; i++ {
		value := fmt.Sprintf("1.%d.0", i)
		order, ok, low := c.compare("npm", value, "2.0.0")
		if order >= 0 || !ok || low {
			t.Fatalf("wrong comparison after eviction: %s", value)
		}
	}
	if c.versionBytes > 1<<20 || c.comparisonBytes > 2<<20 {
		t.Fatal("version caches grew past their budgets")
	}
	vectors := []string{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "AV:N/AC:L/Au:N/C:P/I:P/A:P", "CVSS:3.1/AV:N/AV:L", "invalid"}
	for _, vector := range vectors {
		for i := 0; i < 1100; i++ {
			c.cvssBase(fmt.Sprintf("invalid-%d", i))
		}
		want, wantErr := CVSSBase(vector)
		for i := 0; i < 2; i++ {
			got, err := c.cvssBase(vector)
			if got != want || fmt.Sprint(err) != fmt.Sprint(wantErr) {
				t.Fatalf("cached CVSS changed %q: %v, %v", vector, got, err)
			}
		}
	}
}

func TestQuietMissStillBridgesAdvisoryAliases(t *testing.T) {
	hit := advisory("npm", "fixture", "2.0.0")
	hit.ID, hit.Aliases = "GHSA-hit", []string{"bridge"}
	miss := advisory("npm", "fixture", "0.5.0")
	miss.ID, miss.Aliases = "bridge", []string{"CVE-2026-123456"}
	subjects := []Subject{{Ref: "ref", Name: "fixture", Ecosystem: "npm", Version: "1.0.0"}}
	store := &fakeStore{records: []vulndb.Record{hit, miss}}
	report, err := Run(context.Background(), store, subjects, Options{})
	if err != nil || len(report.Findings) != 1 || report.Findings[0].ID != "CVE-2026-123456" {
		t.Fatalf("quiet miss lost alias bridge: %+v, %v", report.Findings, err)
	}
	again, err := Run(context.Background(), store, subjects, Options{})
	if err != nil || !reflect.DeepEqual(report, again) {
		t.Fatal("matching is nondeterministic")
	}
	ignored, err := Run(context.Background(), store, subjects, Options{IgnoreIDs: []string{"CVE-2026-123456"}})
	if err != nil || len(ignored.Findings) != 0 || ignored.Skipped["ignored"] != 2 {
		t.Fatalf("ignored canonical IDs changed: %+v, %v", ignored, err)
	}
}
