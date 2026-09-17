package scramble

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"time"
)

type scrambleFailWriter struct {
	writes int
	failAt int
	err    error
}

func (w *scrambleFailWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == w.failAt {
		return 0, w.err
	}
	return len(p), nil
}

func TestSecurityScrambleIOFailures(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	want := errors.New("destination unavailable")
	for _, stage := range []struct {
		name string
		call int
	}{{"header", 1}, {"payload", 2}, {"signature", 3}} {
		t.Run(stage.name, func(t *testing.T) {
			w := &scrambleFailWriter{failAt: stage.call, err: want}
			if err := Encrypt(bytes.NewReader([]byte("abc")), w, 3, 3, priv, time.Unix(0, 0)); !errors.Is(err, want) {
				t.Fatalf("write error = %v", err)
			}
		})
	}
	if err := Encrypt(bytes.NewReader(nil), io.Discard, 1, 8, priv, time.Unix(0, 0)); !errors.Is(err, io.EOF) {
		t.Fatalf("short input error = %v", err)
	}
	if err := Encrypt(bytes.NewReader(nil), io.Discard, 0, 1<<30+1, priv, time.Unix(0, 0)); err == nil {
		t.Fatal("excessive chunk accepted")
	}
	var encrypted bytes.Buffer
	if err := Encrypt(bytes.NewReader([]byte("abc")), &encrypted, 3, 3, priv, time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(bytes.NewReader(encrypted.Bytes()), &scrambleFailWriter{failAt: 1, err: want}, nil); !errors.Is(err, want) {
		t.Fatalf("decrypt write error = %v", err)
	}
	for _, n := range []int{0, headerSize - 1, headerSize, headerSize + 2, encrypted.Len() - 1} {
		if _, err := Decrypt(bytes.NewReader(encrypted.Bytes()[:n]), io.Discard, nil); err == nil {
			t.Errorf("truncated file of %d bytes accepted", n)
		}
	}
}

func TestSecurityScrambleHeaderAndEmptyPayload(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	var encrypted bytes.Buffer
	if err := Encrypt(bytes.NewReader(nil), &encrypted, 0, 0, priv, time.Unix(123, 0)); err != nil {
		t.Fatal(err)
	}
	h, err := Decrypt(bytes.NewReader(encrypted.Bytes()), io.Discard, nil)
	if err != nil || h.PlainSize != 0 || h.ChunkSize != 1<<20 || h.CreatedAt.Unix() != 123 {
		t.Fatalf("empty payload header = %#v, %v", h, err)
	}
	for _, chunk := range []uint32{0, 1<<30 + 1} {
		bad := bytes.Clone(encrypted.Bytes())
		binary.BigEndian.PutUint32(bad[8:12], chunk)
		if _, err := Decrypt(bytes.NewReader(bad), io.Discard, nil); err == nil {
			t.Errorf("invalid chunk %d accepted", chunk)
		}
	}
	if _, err := parseHeader(nil); err == nil {
		t.Fatal("empty header accepted")
	}
}
