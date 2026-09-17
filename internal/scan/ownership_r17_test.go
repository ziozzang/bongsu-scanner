package scan

import (
	"fmt"
	"testing"
	"time"
)

func TestR17OwnershipScaling(t *testing.T) {
	for _, owned := range []bool{false, true} {
		t.Run(fmt.Sprint(owned), func(t *testing.T) {
			c := cataloger{seen: map[string]Package{}, installed: map[string][]installedLocation{}}
			const n = 16000
			for i := 0; i < n; i++ {
				v := fmt.Sprint(i)
				p := Package{Type: "pypi", Name: "same", Version: v, Source: "usr/lib/same.dist-info/METADATA"}
				c.seen[v] = p
				key := packageNameKey(p)
				c.installed[key] = append(c.installed[key], installedLocation{version: v, source: p.Source})
			}
			if owned {
				c.ownedPaths = map[string]string{"usr/lib/same.dist-info/METADATA": "rpm:same@1"}
			}
			start := time.Now()
			c.resolveOwnership()
			elapsed := time.Since(start)
			t.Logf("%d versions owned=%v: %s", n, owned, elapsed)
			if elapsed > time.Second {
				t.Fatalf("quadratic ownership resolution: %s", elapsed)
			}
			for _, p := range c.seen {
				if owned && p.Owner != "rpm:same@1" || !owned && p.Owner != "" {
					t.Fatal(p)
				}
			}
		})
	}
}
