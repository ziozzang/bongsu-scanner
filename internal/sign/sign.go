// Package sign implements timestamp-bound detached Ed25519 signatures.
package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

const Version = 1

// Record contains everything required to reconstruct the signed payload.
// The signature covers domain, target digest, signing time, and random salt.
type Record struct {
	Version      int       `json:"version"`
	Algorithm    string    `json:"algorithm"`
	Signer       string    `json:"signer,omitempty"`
	PublicKey    string    `json:"public_key"`
	Target       string    `json:"target,omitempty"`
	DigestSHA256 string    `json:"digest_sha256"`
	SignedAt     time.Time `json:"signed_at"`
	Salt         string    `json:"salt"`
	Signature    string    `json:"signature"`
}

func payload(digest string, at time.Time, salt []byte) []byte {
	return []byte("bongsu-signature-v1\nsha256:" + digest + "\nsigned-at:" +
		at.UTC().Format(time.RFC3339Nano) + "\nsalt:" + base64.RawStdEncoding.EncodeToString(salt) + "\n")
}

func Generate() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func MarshalPrivate(priv ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func MarshalPublic(pub ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

func ParsePrivate(b []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("private key: PEM block not found")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not Ed25519")
	}
	return priv, nil
}

func ParsePublic(b []byte) (ed25519.PublicKey, error) {
	if block, _ := pem.Decode(b); block != nil {
		k, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		pub, ok := k.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("public key is not Ed25519")
		}
		return pub, nil
	}
	raw, err := hex.DecodeString(string(bytesTrimSpace(b)))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key must be PKIX PEM or 32-byte hex")
	}
	return ed25519.PublicKey(raw), nil
}

func bytesTrimSpace(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && (b[start] == ' ' || b[start] == '\n' || b[start] == '\r' || b[start] == '\t') {
		start++
	}
	for end > start && (b[end-1] == ' ' || b[end-1] == '\n' || b[end-1] == '\r' || b[end-1] == '\t') {
		end--
	}
	return b[start:end]
}

func FileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := f.WriteTo(h); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func Create(digest, target, signer string, priv ed25519.PrivateKey, now time.Time) (Record, error) {
	if _, err := hex.DecodeString(digest); err != nil || len(digest) != sha256.Size*2 {
		return Record{}, fmt.Errorf("invalid SHA-256 digest")
	}
	randomSalt := make([]byte, 32)
	if _, err := rand.Read(randomSalt); err != nil {
		return Record{}, err
	}
	now = now.UTC()
	// The effective salt is bound to both fresh randomness and signing time.
	// Thus signed_at is not merely metadata: changing it changes the salt input
	// as well as the canonical signature payload.
	saltInput := append(randomSalt, []byte(now.Format(time.RFC3339Nano))...)
	effectiveSalt := sha256.Sum256(saltInput)
	salt := effectiveSalt[:]
	sig := ed25519.Sign(priv, payload(digest, now, salt))
	return Record{Version: Version, Algorithm: "ed25519", Signer: signer,
		PublicKey: hex.EncodeToString(priv.Public().(ed25519.PublicKey)), Target: target,
		DigestSHA256: digest, SignedAt: now, Salt: base64.RawStdEncoding.EncodeToString(salt),
		Signature: base64.RawStdEncoding.EncodeToString(sig)}, nil
}

func (r Record) Verify(pub ed25519.PublicKey) error {
	if r.Version != Version || r.Algorithm != "ed25519" {
		return fmt.Errorf("unsupported signature format")
	}
	embedded, err := ParsePublic([]byte(r.PublicKey))
	if err != nil {
		return err
	}
	if pub != nil && !pub.Equal(embedded) {
		return fmt.Errorf("signature public key does not match pinned key")
	}
	salt, err := base64.RawStdEncoding.DecodeString(r.Salt)
	if err != nil || len(salt) < 16 {
		return fmt.Errorf("invalid signature salt")
	}
	sig, err := base64.RawStdEncoding.DecodeString(r.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature encoding")
	}
	if !ed25519.Verify(embedded, payload(r.DigestSHA256, r.SignedAt, salt), sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

func ReadRecord(path string) (Record, error) {
	var r Record
	b, err := os.ReadFile(path)
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return r, err
	}
	return r, nil
}

func WriteRecord(path string, r Record) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o644)
}

func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}
