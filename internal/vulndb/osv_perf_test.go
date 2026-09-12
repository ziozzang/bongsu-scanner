package vulndb

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"testing"
)

// A decompressor may return all declared JSON bytes together with a stream
// error. Reading the expected length alone must never suppress that error.
func TestOSVExactSizeReadPreservesStreamError(t *testing.T) {
	body := []byte(osvFixture("OSV-stream", "npm", "example"))
	var archive bytes.Buffer
	w := zip.NewWriter(&archive)
	member, err := w.CreateHeader(&zip.FileHeader{Name: "entry.json", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := member.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(archive.Bytes()), int64(archive.Len()))
	if err != nil {
		t.Fatal(err)
	}
	zr.RegisterDecompressor(zip.Store, func(io.Reader) io.ReadCloser { return io.NopCloser(&osvFailAtEndReader{body: body}) })
	if _, err := decodeOSVMember(zr.File[0], SourceOSV); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("stream error suppressed: %v", err)
	}
}

type osvFailAtEndReader struct{ body []byte }

func (r *osvFailAtEndReader) Read(p []byte) (int, error) {
	n := copy(p, r.body)
	r.body = r.body[n:]
	if len(r.body) == 0 {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}
