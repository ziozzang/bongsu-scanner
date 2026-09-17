package sign

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSecurityFileDigestAndRecordErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "artifact")
	if err := os.WriteFile(path, []byte("abc"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := FileDigest(path); err != nil || got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("digest = %q, %v", got, err)
	}
	for _, path := range []string{dir, filepath.Join(dir, "missing")} {
		if _, err := FileDigest(path); err == nil {
			t.Errorf("FileDigest(%q) accepted unreadable file", path)
		}
		if _, err := ReadRecord(path); err == nil {
			t.Errorf("ReadRecord(%q) accepted unreadable record", path)
		}
	}
	if _, err := ReadRecord(path); err == nil {
		t.Fatal("malformed JSON accepted")
	}
	if err := WriteRecord(dir, Record{}); err == nil {
		t.Fatal("writing record over directory succeeded")
	}
	if err := WriteRecord(path, Record{SignedAt: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)}); err == nil {
		t.Fatal("unrepresentable JSON timestamp accepted")
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "abc" {
		t.Fatalf("failed marshal changed destination: %q, %v", got, err)
	}
}

func TestSecurityRejectsMalformedDER(t *testing.T) {
	for _, typ := range []string{"PRIVATE KEY", "PUBLIC KEY"} {
		data := pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: []byte{0x30, 0x01}})
		if _, err := ParsePrivate(data); err == nil {
			t.Error("malformed private DER accepted")
		}
		if _, err := ParsePublic(data); err == nil {
			t.Error("malformed public DER accepted")
		}
	}
	// A fixed P-256 point gives a deterministic, valid key of the wrong type.
	x, y := elliptic.P256().ScalarBaseMult([]byte{1})
	der, err := x509.MarshalPKIXPublicKey(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePublic(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})); err == nil {
		t.Fatal("ECDSA public key accepted")
	}
	der, err = x509.MarshalPKCS8PrivateKey(&ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: big.NewInt(1)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePrivate(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err == nil {
		t.Fatal("ECDSA private key accepted")
	}
}

func TestSecurityRecordEncodingAndUTC(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	at := time.Date(2026, 9, 17, 12, 0, 0, 123, time.FixedZone("KST", 9*3600))
	r, err := Create(strings.Repeat("a", 64), "artifact", "publisher", priv, at)
	if err != nil {
		t.Fatal(err)
	}
	if !r.SignedAt.Equal(at) || r.SignedAt.Location() != time.UTC {
		t.Fatalf("timestamp not normalized to UTC: %v", r.SignedAt)
	}
	if err := r.Verify(nil); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Record){
		"public key":         func(r *Record) { r.PublicKey = "not hex" },
		"salt encoding":      func(r *Record) { r.Salt = "!" },
		"short salt":         func(r *Record) { r.Salt = "YQ" },
		"signature encoding": func(r *Record) { r.Signature = "!" },
		"short signature":    func(r *Record) { r.Signature = "YQ" },
		"algorithm":          func(r *Record) { r.Algorithm = "rsa" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := r
			mutate(&bad)
			if err := bad.Verify(pub); err == nil {
				t.Fatal("malformed record verified")
			}
		})
	}
	for _, digest := range []string{"", strings.Repeat("g", 64), strings.Repeat("a", 63), strings.Repeat("a", 66)} {
		if _, err := Create(digest, "", "", priv, at); err == nil {
			t.Errorf("invalid digest %q accepted", digest)
		}
	}
	if got := Fingerprint(pub); got != "139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070" {
		t.Fatalf("fingerprint = %s", got)
	}
	parsed, err := ParsePublic([]byte(" \r\n\t" + hex.EncodeToString(pub) + " \r\n\t"))
	if err != nil || !parsed.Equal(pub) {
		t.Fatalf("whitespace-wrapped public key = %x, %v", parsed, err)
	}
}
