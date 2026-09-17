package main

import (
	"errors"
	"io"
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

type analysisFailWriter struct{ remaining int }

func (w *analysisFailWriter) Write(p []byte) (int, error) {
	if w.remaining == 0 {
		return 0, io.ErrClosedPipe
	}
	w.remaining--
	return len(p), nil
}

func TestAnalysisDBMetaWriteErrors(t *testing.T) {
	for _, writes := range []int{0, 1} {
		w := &analysisFailWriter{remaining: writes}
		err := printDBMetaTo(w, vulndb.Meta{Sources: []vulndb.SourceMeta{{Name: "osv"}}})
		if !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("after %d successful writes: got %v, want write error", writes, err)
		}
	}
}

type analysisClosingCatalog struct {
	vulndb.Store
	err error
}

func (s analysisClosingCatalog) Close() error { return s.err }

func TestAnalysisCatalogClosePreservesErrors(t *testing.T) {
	changed := errors.New("catalog changed before close")
	for _, primary := range []error{nil, io.ErrClosedPipe} {
		result := primary
		closeCommandCatalog(analysisClosingCatalog{err: changed}, &result)
		if !errors.Is(result, changed) || primary != nil && !errors.Is(result, primary) {
			t.Fatalf("close discarded catalog/primary error: %v", result)
		}
	}
}
