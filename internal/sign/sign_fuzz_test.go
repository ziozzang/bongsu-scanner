package sign

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func fuzzSignedRecord(t testing.TB) (Record, ed25519.PublicKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	digest := hex.EncodeToString(make([]byte, 32))
	rec, err := Create(digest, "SHA256SUMS", "release <release@example.com>", priv, time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return rec, priv.Public().(ed25519.PublicKey)
}

func FuzzVerifyRecord(f *testing.F) {
	rec, _ := fuzzSignedRecord(f)
	good, _ := json.Marshal(rec)
	f.Add(good)
	v1 := rec
	v1.Version = 1
	b, _ := json.Marshal(v1)
	f.Add(b)
	f.Add([]byte(`{"version":2,"algorithm":"ed25519","public_key":"` + strings.Repeat("00", 32) + `","digest_sha256":"","signed_at":"2026-09-17T00:00:00Z","salt":"AAAAAAAAAAAAAAAAAAAAAA","signature":"AA"}`))
	f.Add([]byte(`{"version":2,"algorithm":"ed25519","public_key":"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----","salt":"x","signature":"y"}`))
	f.Add([]byte(`{"version":1,"algorithm":"rsa"}`))
	f.Add([]byte(`{"signed_at":"not a time"}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var r Record
		if err := json.Unmarshal(data, &r); err != nil {
			return
		}
		err := r.Verify(nil)
		_, pinned := fuzzSignedRecord(t)
		errPinned := r.Verify(pinned)
		other := ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))
		errOther := r.Verify(other)
		if err == nil {
			// A record that verifies must carry the embedded key it verifies with.
			embedded, perr := ParsePublic([]byte(r.PublicKey))
			if perr != nil {
				t.Fatalf("verified record with unparseable key: %v", perr)
			}
			if embedded.Equal(pinned) != (errPinned == nil) {
				t.Fatalf("pinned verification disagrees: embedded==pinned %v err %v", embedded.Equal(pinned), errPinned)
			}
			if errOther == nil && !embedded.Equal(other) {
				t.Fatalf("record verified under an unrelated pinned key")
			}
			if r.Version != 1 && r.Version != 2 {
				t.Fatalf("verified unsupported version %d", r.Version)
			}
			// Re-encoding a verified record must verify again.
			b, _ := json.Marshal(r)
			var again Record
			if json.Unmarshal(b, &again) != nil || again.Verify(nil) != nil {
				t.Fatalf("re-encoded record does not verify")
			}
			if r.Authenticated() != (r.Version == 2) {
				t.Fatalf("Authenticated() mismatch for version %d", r.Version)
			}
		} else if errPinned == nil || errOther == nil {
			t.Fatalf("pinned verification succeeded where unpinned failed: %v", err)
		}
	})
}

func FuzzParseKeys(f *testing.F) {
	_, pub := fuzzSignedRecord(f)
	pem, _ := MarshalPublic(pub)
	f.Add(pem)
	f.Add([]byte(hex.EncodeToString(pub)))
	f.Add([]byte(" \n" + hex.EncodeToString(pub) + "\r\n"))
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	privPEM, _ := MarshalPrivate(priv)
	f.Add(privPEM)
	f.Add([]byte("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"))
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\n\n-----END PRIVATE KEY-----\n"))
	f.Add([]byte("zz"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if pub, err := ParsePublic(data); err == nil {
			if len(pub) != ed25519.PublicKeySize {
				t.Fatalf("ParsePublic returned %d bytes", len(pub))
			}
			// A parsed key must be usable for verification without panicking.
			_ = ed25519.Verify(pub, []byte("m"), make([]byte, ed25519.SignatureSize))
			_ = Fingerprint(pub)
			out, err := MarshalPublic(pub)
			if err != nil {
				t.Fatalf("MarshalPublic: %v", err)
			}
			if again, err := ParsePublic(out); err != nil || !again.Equal(pub) {
				t.Fatalf("public key does not round trip: %v", err)
			}
		}
		if priv, err := ParsePrivate(data); err == nil {
			if len(priv) != ed25519.PrivateKeySize {
				t.Fatalf("ParsePrivate returned %d bytes", len(priv))
			}
			digest := hex.EncodeToString(make([]byte, 32))
			rec, err := Create(digest, "t", "s", priv, time.Now())
			if err != nil {
				t.Fatalf("Create with parsed key: %v", err)
			}
			if err := rec.Verify(priv.Public().(ed25519.PublicKey)); err != nil {
				t.Fatalf("Verify with parsed key: %v", err)
			}
		}
	})
}
