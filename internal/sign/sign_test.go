package sign

import (
	"crypto/ed25519"
	"testing"
	"time"
)

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
