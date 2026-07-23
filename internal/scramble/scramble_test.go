package scramble

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/sign"
)

func TestRoundTripAcrossChunks(t *testing.T) {
	pub, priv, _ := sign.Generate()
	plain := bytes.Repeat([]byte("bongsu-\x00\xff"), 1000)
	var encrypted bytes.Buffer
	if err := Encrypt(bytes.NewReader(plain), &encrypted, uint64(len(plain)), 37, priv, time.Unix(1234, 0)); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted.Bytes()[headerSize:len(encrypted.Bytes())-ed25519.SignatureSize], []byte("bongsu-")) {
		t.Fatal("plaintext pattern remains in scrambled payload")
	}
	var restored bytes.Buffer
	h, err := Decrypt(bytes.NewReader(encrypted.Bytes()), &restored, pub)
	if err != nil {
		t.Fatal(err)
	}
	if h.ChunkSize != 37 || !bytes.Equal(restored.Bytes(), plain) {
		t.Fatal("round trip mismatch")
	}
}

func TestTamperRejected(t *testing.T) {
	_, priv, _ := sign.Generate()
	var encrypted bytes.Buffer
	plain := []byte("sensitive-ish binary")
	if err := Encrypt(bytes.NewReader(plain), &encrypted, uint64(len(plain)), 8, priv, time.Now()); err != nil {
		t.Fatal(err)
	}
	b := encrypted.Bytes()
	b[headerSize+2] ^= 1
	var out bytes.Buffer
	if _, err := Decrypt(bytes.NewReader(b), &out, nil); err == nil {
		t.Fatal("tampered scramble accepted")
	}
}
