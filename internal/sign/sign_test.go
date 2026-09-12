package sign

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestV2AuthenticatesRecordFields(t *testing.T) {
	pub, priv, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	r, err := Create(strings.Repeat("a", 64), "artifact", "tester", priv, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if r.Version != 2 {
		t.Errorf("Create emitted version %d, want 2", r.Version)
	}
	path := filepath.Join(t.TempDir(), "artifact.sig")
	if err := WriteRecord(path, r); err != nil {
		t.Fatal(err)
	}
	r, err = ReadRecord(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Verify(pub); err != nil {
		t.Fatal(err)
	}
	if !r.Authenticated() {
		t.Fatal("verified v2 metadata reported as unauthenticated")
	}
	for name, mutate := range map[string]func(*Record){
		"signer":    func(r *Record) { r.Signer = "forged publisher" },
		"target":    func(r *Record) { r.Target = "other artifact" },
		"digest":    func(r *Record) { r.DigestSHA256 = strings.Repeat("b", 64) },
		"downgrade": func(r *Record) { r.Version = 1 },
		"unknown":   func(r *Record) { r.Version = 3 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := r
			mutate(&bad)
			if err := bad.Verify(pub); err == nil {
				t.Fatal("modified record accepted")
			}
		})
	}
}

func TestV2FieldBoundaries(t *testing.T) {
	pub, priv, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{"ab", "c"}, {"a\n", "b"}, {"a\x00", "b"}, {"", "한글"}} {
		r, err := Create(strings.Repeat("a", 64), pair[0], pair[1], priv, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Verify(pub); err != nil {
			t.Fatal(err)
		}
		// Preserve the concatenation while moving a byte across the field boundary.
		joined := r.Target + r.Signer
		boundary := (len(r.Target) + 1) % len(joined)
		r.Target, r.Signer = joined[:boundary], joined[boundary:]
		if err := r.Verify(pub); err == nil {
			t.Fatalf("ambiguous field boundaries accepted for %q", pair)
		}
	}
}

func TestLegacyV1Record(t *testing.T) {
	// Freeze the legacy canonical payload independently of the implementation.
	const canonical = "bongsu-signature-v1\nsha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nsigned-at:2026-07-23T10:20:30.000000123Z\nsalt:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	r := Record{
		Version: 1, Algorithm: "ed25519", Signer: "legacy", Target: "artifact",
		PublicKey: hex.EncodeToString(pub), DigestSHA256: strings.Repeat("a", 64),
		SignedAt:  time.Date(2026, 7, 23, 10, 20, 30, 123, time.UTC),
		Salt:      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Signature: base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, []byte(canonical))),
	}
	if err := r.Verify(pub); err != nil {
		t.Fatal(err)
	}
	if r.Authenticated() {
		t.Fatal("legacy metadata reported as authenticated")
	}
	r.Signer, r.Target = "forged label", "another target"
	if err := r.Verify(pub); err != nil {
		t.Fatalf("legacy metadata must remain unauthenticated: %v", err)
	}
	for name, mutate := range map[string]func(*Record){
		"timestamp": func(r *Record) { r.SignedAt = r.SignedAt.Add(time.Second) },
		"digest":    func(r *Record) { r.DigestSHA256 = strings.Repeat("b", 64) },
		"salt":      func(r *Record) { r.Salt = "AAAAAAAAAAAAAAAAAAAAAA" },
		"upgrade":   func(r *Record) { r.Version = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := r
			mutate(&bad)
			if err := bad.Verify(pub); err == nil {
				t.Fatal("modified legacy record accepted")
			}
		})
	}
}

func TestTimestampAndSaltAreSigned(t *testing.T) {
	_, priv, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 7, 23, 10, 20, 30, 123, time.UTC)
	r, err := Create("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "a.sha256", "tester", priv, at)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	if err := r.Verify(pub); err != nil {
		t.Fatal(err)
	}
	t.Run("timestamp tamper", func(t *testing.T) {
		bad := r
		bad.SignedAt = bad.SignedAt.Add(time.Nanosecond)
		if err := bad.Verify(pub); err == nil {
			t.Fatal("tampered signing time accepted")
		}
	})
	t.Run("salt tamper", func(t *testing.T) {
		bad := r
		bad.Salt = "AAAAAAAAAAAAAAAAAAAAAA"
		if err := bad.Verify(pub); err == nil {
			t.Fatal("tampered salt accepted")
		}
	})
	t.Run("wrong key", func(t *testing.T) {
		other, _, _ := Generate()
		if err := r.Verify(other); err == nil {
			t.Fatal("wrong pinned key accepted")
		}
	})
}

func TestKeyPEMRoundTrip(t *testing.T) {
	pub, priv, _ := Generate()
	privatePEM, _ := MarshalPrivate(priv)
	gotPriv, err := ParsePrivate(privatePEM)
	if err != nil || !gotPriv.Equal(priv) {
		t.Fatalf("private round trip: %v", err)
	}
	publicPEM, _ := MarshalPublic(pub)
	gotPub, err := ParsePublic(publicPEM)
	if err != nil || !gotPub.Equal(pub) {
		t.Fatalf("public round trip: %v", err)
	}
}
