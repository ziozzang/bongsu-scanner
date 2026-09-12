package vulndb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

// contextReader bounds cancellation latency to one underlying read. It does
// not interrupt a blocked kernel read; regular catalog files are read locally.
type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.r.Read(p)
	if canceled := r.ctx.Err(); canceled != nil {
		return n, canceled
	}
	return n, err
}

func hashFileContext(ctx context.Context, path string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	digest, err := hashReaderContext(ctx, f)
	if err != nil {
		return "", err
	}
	return digest, ctx.Err()
}

func hashReaderContext(ctx context.Context, r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, contextReader{ctx: ctx, r: r}); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), ctx.Err()
}

// LookupContext uses cancellable lookup when supported. Older Store
// implementations remain compatible, with cancellation checked around the call.
func LookupContext(ctx context.Context, store Store, ecosystem, name string) ([]Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if reader, ok := store.(interface {
		LookupContext(context.Context, string, string) ([]Record, error)
	}); ok {
		return reader.LookupContext(ctx, ecosystem, name)
	}
	records, err := store.Lookup(ecosystem, name)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return records, nil
}
