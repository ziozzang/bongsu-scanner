// Package scramble implements a signed reversible binary scrambler.
//
// This is deliberately not confidentiality encryption: ciphertext can be
// restored by anyone holding the public key. The private key authorizes the
// scrambled artifact, while a public-key-derived stream obfuscates its bytes.
package scramble

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

var magic = [8]byte{'B', 'O', 'N', 'G', 'S', 'U', '0', '1'}

const headerSize = 8 + 4 + 8 + 8 + 32 + 32

type Header struct {
	ChunkSize uint32
	PlainSize uint64
	CreatedAt time.Time
	Salt      [32]byte
	PublicKey ed25519.PublicKey
}

func Encrypt(in io.Reader, out io.Writer, size uint64, chunkSize int, priv ed25519.PrivateKey, now time.Time) error {
	if chunkSize <= 0 {
		chunkSize = 1 << 20
	}
	if chunkSize > 1<<30 {
		return fmt.Errorf("chunk size too large")
	}
	var salt [32]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	header := makeHeader(uint32(chunkSize), size, now.UTC(), salt, pub)
	if _, err := out.Write(header); err != nil {
		return err
	}
	h := sha256.New()
	h.Write(header)
	buf := make([]byte, chunkSize)
	var offset uint64
	for offset < size {
		want := uint64(len(buf))
		if left := size - offset; left < want {
			want = left
		}
		n, err := io.ReadFull(in, buf[:want])
		if err != nil {
			return fmt.Errorf("input ended at %d of %d bytes: %w", offset, size, err)
		}
		xor(buf[:n], pub, salt[:], offset)
		if _, err := out.Write(buf[:n]); err != nil {
			return err
		}
		h.Write(buf[:n])
		offset += uint64(n)
	}
	sig := ed25519.Sign(priv, h.Sum(nil))
	_, err := out.Write(sig)
	return err
}

func Decrypt(in io.Reader, out io.Writer, pub ed25519.PublicKey) (Header, error) {
	raw := make([]byte, headerSize)
	if _, err := io.ReadFull(in, raw); err != nil {
		return Header{}, err
	}
	hdr, err := parseHeader(raw)
	if err != nil {
		return Header{}, err
	}
	if pub != nil && !pub.Equal(hdr.PublicKey) {
		return Header{}, fmt.Errorf("scramble key does not match pinned public key")
	}
	if pub == nil {
		pub = hdr.PublicKey
	}
	hash := sha256.New()
	hash.Write(raw)
	buf := make([]byte, int(hdr.ChunkSize))
	var offset uint64
	for offset < hdr.PlainSize {
		want := uint64(len(buf))
		if left := hdr.PlainSize - offset; left < want {
			want = left
		}
		n, err := io.ReadFull(in, buf[:want])
		if err != nil {
			return Header{}, fmt.Errorf("truncated scrambled payload: %w", err)
		}
		hash.Write(buf[:n])
		xor(buf[:n], pub, hdr.Salt[:], offset)
		if _, err := out.Write(buf[:n]); err != nil {
			return Header{}, err
		}
		offset += uint64(n)
	}
	sig := make([]byte, ed25519.SignatureSize)
	if _, err := io.ReadFull(in, sig); err != nil {
		return Header{}, fmt.Errorf("signature missing: %w", err)
	}
	var extra [1]byte
	if n, _ := in.Read(extra[:]); n != 0 {
		return Header{}, fmt.Errorf("trailing data after scramble signature")
	}
	if !ed25519.Verify(pub, hash.Sum(nil), sig) {
		return Header{}, fmt.Errorf("scramble signature verification failed")
	}
	return hdr, nil
}

func makeHeader(chunk uint32, size uint64, at time.Time, salt [32]byte, pub ed25519.PublicKey) []byte {
	b := make([]byte, headerSize)
	copy(b, magic[:])
	binary.BigEndian.PutUint32(b[8:12], chunk)
	binary.BigEndian.PutUint64(b[12:20], size)
	binary.BigEndian.PutUint64(b[20:28], uint64(at.Unix()))
	copy(b[28:60], salt[:])
	copy(b[60:92], pub)
	return b
}

func parseHeader(b []byte) (Header, error) {
	if len(b) != headerSize || string(b[:8]) != string(magic[:]) {
		return Header{}, fmt.Errorf("not a bongsu scramble file")
	}
	h := Header{ChunkSize: binary.BigEndian.Uint32(b[8:12]), PlainSize: binary.BigEndian.Uint64(b[12:20]),
		CreatedAt: time.Unix(int64(binary.BigEndian.Uint64(b[20:28])), 0).UTC(),
		PublicKey: append(ed25519.PublicKey(nil), b[60:92]...)}
	copy(h.Salt[:], b[28:60])
	if h.ChunkSize == 0 || h.ChunkSize > 1<<30 {
		return Header{}, fmt.Errorf("invalid chunk size")
	}
	return h, nil
}

func xor(b, pub, salt []byte, offset uint64) {
	var block [8]byte
	for len(b) > 0 {
		binary.BigEndian.PutUint64(block[:], offset/sha256.Size)
		h := sha256.New()
		h.Write([]byte("bongsu-scramble-v1"))
		h.Write(pub)
		h.Write(salt)
		h.Write(block[:])
		stream := h.Sum(nil)
		start := int(offset % sha256.Size)
		n := len(stream) - start
		if n > len(b) {
			n = len(b)
		}
		for i := 0; i < n; i++ {
			b[i] ^= stream[start+i]
		}
		b = b[n:]
		offset += uint64(n)
	}
}
