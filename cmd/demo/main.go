package main

import (
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	dnscrypt "github.com/DNSFilter/dnscrypt-transport"
	"github.com/miekg/dns"
	"golang.org/x/crypto/nacl/box"
)

var resolverMagic = []byte{0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38}

const nonceLength = 24
const keyLength = 32

type Certificate struct {
	PrivateKey []byte
	dnscrypt.Certificate
}

func getPEMSection(b []byte, typ string) []byte {
	for len(b) > 0 {
		var p *pem.Block
		p, b = pem.Decode(b)
		if p.Type == typ {
			return p.Bytes
		}
	}
	return nil
}

type dec struct {
	certs map[string]*Certificate
	r     dns.Reader
}

func (d *dec) ReadTCP(conn net.Conn, timeout time.Duration) ([]byte, error) {
	// XXX implement
	return nil, nil
}

func unpad(b []byte) ([]byte, bool) {
	if len(b) == 0 {
		return b, false
	}
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] == 0x80 {
			return b[:i], true
		}
		if b[i] != 0 {
			return b, false
		}
	}
	return b, false
}

func (d *dec) ReadUDP(conn *net.UDPConn, timeout time.Duration) ([]byte, *dns.SessionUDP, error) {
	b, s, err := d.r.ReadUDP(conn, timeout)
	if err != nil {
		return b, s, err
	}
	if len(b) < 8 {
		return b, s, nil
	}

	// select certificate based on magic bytes
	magic := b[:8]
	cert := d.certs[string(magic)]
	if cert == nil {
		// Not a valid magic string, assume it's an unencrypted request
		return b, s, nil
	}
	// We only support X25519-XSalsa20Poly1305 certificates.
	// Otherwise, we'd have to inspect the cert's encryption method.
	var (
		clientPub    [keyLength]byte
		resolverPriv [keyLength]byte
		nonce        [nonceLength]byte
	)
	copy(clientPub[:], b[8:40])
	// the query contains half the nonce, the other half is all
	// zeroes.
	copy(nonce[:], b[40:52])
	copy(resolverPriv[:], cert.PrivateKey)
	msg := b[52:]
	out := make([]byte, 0, len(msg)-box.Overhead)
	out, ok := box.Open(out, msg, &nonce, &clientPub, &resolverPriv)

	if !ok {
		log.Println("couldn't decode query")
		return nil, s, nil
	}

	unpadded, ok := unpad(out)
	if !ok {
		log.Println("invalid padding")
		return nil, s, nil
	}

	return unpadded, s, nil
}

func escapeTXT(msg []byte) string {
	s := []byte{}
	for _, b := range msg {
		switch b {
		case '"', '\\':
			s = append(s, '\\', b)
		default:
			if b < 32 || b > 127 { // unprintable
				var buf [3]byte
				bufs := strconv.AppendInt(buf[:0], int64(b), 10)
				s = append(s, '\\')
				for i := 0; i < 3-len(bufs); i++ {
					s = append(s, '0')
				}
				for _, r := range bufs {
					s = append(s, r)
				}
			} else {
				s = append(s, b)
			}
		}
	}
	return string(s)
}

type responseWriter struct {
	dnscryptDomain string
	nonce          [nonceLength]byte
	sharedKey      [keyLength]byte
	dns.ResponseWriter
}

func (rw *responseWriter) WriteMsg(msg *dns.Msg) error {
	nonce := rw.nonce
	if _, err := io.ReadFull(rand.Reader, nonce[nonceLength/2:]); err != nil {
		panic(err)
	}
	// XXX pad response
	packed, err := msg.Pack()
	if err != nil {
		return err
	}
	out := make([]byte, len(packed)+box.Overhead)
	box.SealAfterPrecomputation(out, packed, &nonce, &rw.sharedKey)

	// XXX UDP responses mustn't be larger than the request, to guard
	// against amplification attacks
	_, err = rw.ResponseWriter.Write(out)
	return err
}

type Resolver struct {
	Name            string
	Handler         dns.Handler
	Certificates    []*Certificate
	GetCertificates func() ([]*Certificate, error)
}

func (rv *Resolver) ServeDNS(w dns.ResponseWriter, msg *dns.Msg) {
	q := msg.Question[0]
	if q.Qtype == dns.TypeTXT || strings.ToLower(q.Name) == strings.ToLower(rv.Name) {
		// Serve certificates
		rv.certificateHandler(w, msg)
		return
	}
	// Serve generic query
	rw := &responseWriter{
		dnscryptDomain: XXX,
		nonce:          XXX,
		sharedKey:      XXX,
		ResponseWriter: w,
	}
	rv.Handler.ServeDNS(rw, msg)
	debug.Stack()
	return
}

func (rv *Resolver) certificateHandler(w dns.ResponseWriter, msg *dns.Msg) {
	resp := &dns.Msg{}
	resp.SetReply(msg)
	hdr := dns.RR_Header{
		Name:   msg.Question[0].Name,
		Ttl:    3600,
		Class:  dns.ClassINET,
		Rrtype: dns.TypeTXT,
	}
	for _, cert := range rv.Certificates {
		// OPT(dh): cache this computation
		// we have to use escapeTXT because miekg/dns unescapes
		// the value, and our binary data can contain valid escape
		// sequences.
		b := escapeTXT(cert.Bytes())
		// do we need N answers, or 1 answer with N txt values?
		resp.Answer = append(resp.Answer, &dns.TXT{Hdr: hdr, Txt: []string{b}})
	}
	log.Println("Sending response")
	log.Println(w.WriteMsg(resp))
}

func (rv *Resolver) DecorateReader() func(r dns.Reader) dns.Reader {
	return func(r dns.Reader) dns.Reader {
		return &dec{
			certs: map[string]*Certificate{
				string(rv.Certificates[0].ClientMagic): rv.Certificates[0],
			},
			r: r,
		}
	}
}

func main() {
	b, _ := ioutil.ReadFile("cert.cert")
	// XXX guard against malformed input file
	cert, err := dnscrypt.ParseCertificate(getPEMSection(b, "CERTIFICATE"))
	if err != nil {
		log.Fatal(err)
	}
	certs := []*Certificate{
		&Certificate{
			PrivateKey:  getPEMSection(b, "PRIVATE KEY"),
			Certificate: *cert,
		},
	}
	const domain = "2.dnscrypt-cert.local."
	resolver := &Resolver{
		Name:         domain,
		Handler:      dns.DefaultServeMux,
		Certificates: certs,
	}

	srv := &dns.Server{
		Addr:           "localhost:9999",
		Net:            "udp",
		DecorateReader: resolver.DecorateReader(),
		Handler:        resolver,
	}
	dns.HandleFunc(".", func(w dns.ResponseWriter, msg *dns.Msg) {
		log.Println(msg)
	})
	fmt.Println(srv.ListenAndServe())
}
