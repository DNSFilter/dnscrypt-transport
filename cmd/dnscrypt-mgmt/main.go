package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	dnscrypt "github.com/DNSFilter/dnscrypt-transport"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
)

const (
	pemCertificateType        = "CERTIFICATE"
	pemPublicProviderKeyType  = "PUBLIC KEY"
	pemPrivateProviderKeyType = "PRIVATE KEY"
)

func generateProviderKey() {
	// dnscrypt-mgmt generate-provider-key
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalln("couldn't generate provider key pair:", err)
	}

	pem.Encode(os.Stdout,
		&pem.Block{
			Type:  pemPublicProviderKeyType,
			Bytes: pub,
		})
	pem.Encode(os.Stdout,
		&pem.Block{
			Type:  pemPrivateProviderKeyType,
			Bytes: priv,
		})
}

func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b.Type != pemPrivateProviderKeyType {
			continue
		}
		if len(b.Bytes) != ed25519.PrivateKeySize {
			continue
		}
		return ed25519.PrivateKey(b.Bytes), nil
	}
	return nil, errors.New("no valid private key found")
}

func generateCertificate(privPath string) {
	// dnscrypt-mgmt generate-certificate <private.pem>
	signer, err := readPrivateKey(privPath)
	if err != nil {
		log.Fatalln("couldn't load provider key:", err)
	}

	var priv, pub [32]byte
	if _, err := io.ReadFull(rand.Reader, priv[:]); err != nil {
		panic(err)
	}
	curve25519.ScalarBaseMult(&pub, &priv)
	now := time.Now()
	cert := dnscrypt.Certificate{
		PublicKey:   pub,
		ClientMagic: pub[:8],
		Serial:      0, // TODO
		// allow for some clock drift
		Start: now.Add(-5 * time.Minute),
		// make sure the total time doesn't exceed 24 hours, or
		// dnsclient-proxy will "helpfully" reject it
		End: now.Add(24*time.Hour - 5*time.Minute),
	}
	cert.Sign(signer)
	pem.Encode(os.Stdout,
		&pem.Block{
			Type:  pemCertificateType,
			Bytes: cert.Bytes(),
		})
	pem.Encode(os.Stdout,
		&pem.Block{
			Type:  pemPublicProviderKeyType,
			Bytes: pub[:],
		})
	pem.Encode(os.Stdout,
		&pem.Block{
			Type:  pemPrivateProviderKeyType,
			Bytes: priv[:],
		})
}

func printCertificate(path string) {
	// dnscrypt-mgmt print-certificate <cert.cert>
	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal("couldn't read file:", err)
	}
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b.Type != pemCertificateType {
			continue
		}

		cert, _ := dnscrypt.ParseCertificate(b.Bytes)
		f := `Resolver key: %s
Serial: %d
Client magic: %x
Valid from: %s
Valid until: %s
Signature: %x
`
		fmt.Printf(f,
			formatPublicKey(cert.PublicKey[:]), cert.Serial, cert.ClientMagic, cert.Start, cert.End, cert.Signature)
		break
	}
}

func formatPublicKey(key []byte) string {
	parts := make([]string, 0, len(key)/2)
	for i := 0; i < len(key)/2; i++ {
		parts = append(parts, hex.EncodeToString(key[i*2:(i+1)*2]))
	}
	return strings.Join(parts, ":")
}

func printPublicKey(path string) {
	// dnscrypt-mgmt print-public-key <input.pem>
	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal("couldn't read file:", err)
	}
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b.Type != pemPublicProviderKeyType {
			continue
		}
		fmt.Println(formatPublicKey(b.Bytes))

		break
	}
}

func main() {
	log.SetFlags(0)
	switch os.Args[1] {
	case "generate-provider-key":
		generateProviderKey()
	case "generate-certificate":
		generateCertificate(os.Args[2])
	case "print-certificate":
		printCertificate(os.Args[2])
	case "print-public-key":
		printPublicKey(os.Args[2])
	}
}
