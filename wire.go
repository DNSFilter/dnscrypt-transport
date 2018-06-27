package dnscrypt

import (
	"crypto/rand"
	"encoding/binary"
	"time"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/box"
)

// Magic protocol bytes.
const (
	certMagic               = "DNSC"
	protocolMinorVersion    = "\x00\x00"
	x25519XSalsa20Poly1305  = "\x00\x01"
	x25519XChacha20Poly1305 = "\x00\x02"
)

const (
	MagicLength        = 8
	MinimumQueryLength = 52
	NonceLength        = 24
	KeyLength          = 32
)

var ResolverMagic = []byte{0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38}

type Certificate struct {
	PublicKey   [32]byte
	PrivateKey  [32]byte
	ClientMagic []byte
	Serial      uint32
	Start       time.Time
	End         time.Time
	Extensions  []byte
	Signature   []byte
}

// Bytes returns the serialized form of a Certificate. It is in the
// correct form for use in TXT records.
func (c *Certificate) Bytes() []byte {
	var b []byte
	scratch := make([]byte, 4)
	b = append(b, certMagic...)
	b = append(b, x25519XSalsa20Poly1305...)
	b = append(b, protocolMinorVersion...)
	b = append(b, c.Signature...)
	b = append(b, c.PublicKey[:]...)
	b = append(b, c.ClientMagic...)

	binary.BigEndian.PutUint32(scratch, c.Serial)
	b = append(b, scratch...)

	binary.BigEndian.PutUint32(scratch, uint32(c.Start.Unix()))
	b = append(b, scratch...)

	binary.BigEndian.PutUint32(scratch, uint32(c.End.Unix()))
	b = append(b, scratch...)

	// XXX at this point, check that the data is of the expected length
	b = append(b, c.Extensions...)
	return b
}

func ParseCertificate(b []byte) (*Certificate, error) {
	// XXX check b for minimum length
	c := &Certificate{}
	b = b[4:] // skip magic bytes
	b = b[4:] // skip version
	c.Signature = b[0:64]
	copy(c.PublicKey[:], b[64:96])
	c.ClientMagic = b[96:104]
	c.Serial = binary.BigEndian.Uint32(b[104:108])
	c.Start = time.Unix(int64(binary.BigEndian.Uint32(b[108:112])), 0)
	c.End = time.Unix(int64(binary.BigEndian.Uint32(b[112:116])), 0)
	c.Extensions = b[116:]
	return c, nil
}

// Sign signs certificate c, setting its Signature field.
func (c *Certificate) Sign(pkey ed25519.PrivateKey) {
	// (<resolver-pk> <client-magic> <serial> <ts-start> <ts-end> <extensions>)
	var b []byte
	scratch := make([]byte, 4)

	b = append(b, c.PublicKey[:]...)
	b = append(b, c.ClientMagic...)

	binary.BigEndian.PutUint32(scratch, c.Serial)
	b = append(b, scratch...)

	binary.BigEndian.PutUint32(scratch, uint32(c.Start.Unix()))
	b = append(b, scratch...)

	binary.BigEndian.PutUint32(scratch, uint32(c.End.Unix()))
	b = append(b, scratch...)

	b = append(b, c.Extensions...)
	c.Signature = ed25519.Sign(pkey, b)
}

func Pad(b []byte) []byte {
	n := len(b) + 1
	n = n + 64 - n%64
	out := make([]byte, n)
	copy(out, b)
	out[len(b)] = 0x80
	return out
}

type Config struct {
	GetCertificates func() ([]*Certificate, error)
}

type Session struct {
	Key   [32]byte
	Nonce [24]byte
}

func (s *Session) Encrypt(m []byte) []byte {
	nonce := s.Nonce
	if _, err := rand.Read(nonce[NonceLength/2:]); err != nil {
		panic(err)
	}

	var out []byte
	out = append(out, ResolverMagic...)
	out = append(out, nonce[:]...)
	m = Pad(m)
	ct := box.SealAfterPrecomputation(nil, m, &nonce, &s.Key)
	out = append(out, ct...)
	return out
}

func Decrypt(cert *Certificate, m []byte) ([]byte, *Session, bool) {
	if len(m) < MinimumQueryLength {
		return nil, nil, false
	}

	var (
		clientPub [KeyLength]byte
		nonce     [NonceLength]byte
	)
	copy(clientPub[:], m[8:40])
	// the query contains half the nonce, the other half is all
	// zeroes.
	copy(nonce[:], m[40:52])
	msg := m[52:]
	out := make([]byte, 0, len(msg)-box.Overhead)
	var sharedKey [32]byte
	box.Precompute(&sharedKey, &clientPub, &cert.PrivateKey)
	out, ok := box.OpenAfterPrecomputation(out, msg, &nonce, &sharedKey)
	if !ok {
		return nil, nil, false
	}

	// XXX handle padding

	return out, &Session{
		Key:   sharedKey,
		Nonce: nonce,
	}, true
}
