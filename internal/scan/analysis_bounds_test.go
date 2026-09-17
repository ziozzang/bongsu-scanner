package scan

import (
	"encoding/binary"
	"io"
	"testing"
)

type analysisELFReader struct{ offsets []int64 }

func (r *analysisELFReader) ReadAt(p []byte, off int64) (int, error) {
	r.offsets = append(r.offsets, off)
	if off != 0 {
		return 0, io.EOF
	}
	copy(p, "\x7fELF\x02\x01")
	binary.LittleEndian.PutUint64(p[40:48], 1<<63)
	binary.LittleEndian.PutUint16(p[58:60], 64)
	binary.LittleEndian.PutUint16(p[60:62], 1)
	return len(p), nil
}

func TestAnalysisRodataRejectsNegativeSize(t *testing.T) {
	r := &analysisELFReader{}
	if off, size := binaryRodata(r, -1); off != 0 || size != 0 {
		t.Fatalf("invalid rodata range: %d, %d", off, size)
	}
	for _, off := range r.offsets {
		if off < 0 {
			t.Fatalf("untrusted ELF offset wrapped into negative ReadAt offset: %d", off)
		}
	}
}
