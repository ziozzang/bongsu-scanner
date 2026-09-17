package vulndb

import (
	"context"
	"fmt"
	"sort"
)

// buildSQLite builds a catalog from an in-memory record map. Production code
// streams records (see buildSQLiteStream and Convert); tests keep this
// convenience wrapper.
func buildSQLite(ctx context.Context, dir string, records map[string]*Record, meta *Meta) error {
	return buildSQLiteStream(ctx, dir, func(emit Emit) error {
		ids := make([]string, 0, len(records))
		for id := range records {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			r := records[id]
			if r == nil || r.ID != id {
				return fmt.Errorf("invalid catalog record %q", id)
			}
			if err := emit(r); err != nil {
				return err
			}
		}
		return nil
	}, meta)
}
