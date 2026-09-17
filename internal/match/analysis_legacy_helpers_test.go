package match

import (
	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

// Legacy adapters retained for existing regression fixtures only.
func affectedVersion(eco, v string, a vulndb.Affected) (bool, []string, bool, string) {
	cache := newVersionCache()
	return cache.affectedVersion(eco, v, cache.prepareAffected(eco, a))
}
