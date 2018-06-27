package main

import (
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"strconv"

	dnscrypt "github.com/DNSFilter/dnscrypt-transport"
	"github.com/miekg/dns"
)

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

func main() {
	const domain = "2.dnscrypt-cert.local."

	b, _ := ioutil.ReadFile("cert.cert")
	cert, err := dnscrypt.ParseCertificate(getPEMSection(b, "CERTIFICATE"))
	if err != nil {
		log.Fatal(err)
	}
	copy(cert.PrivateKey[:], getPEMSection(b, "PRIVATE KEY"))

	certs := []*dnscrypt.Certificate{cert}
	srv := &dns.Server{
		Addr: "localhost:9999",
		Net:  "udp",
		DNSCryptConfig: &dnscrypt.Config{
			GetCertificates: func() ([]*dnscrypt.Certificate, error) {
				return certs, nil
			},
		},
	}

	dns.HandleFunc(domain, func(w dns.ResponseWriter, msg *dns.Msg) {
		// TODO move this into miekg/dns
		resp := &dns.Msg{}
		resp.SetReply(msg)
		hdr := dns.RR_Header{
			Name:   msg.Question[0].Name,
			Ttl:    3600,
			Class:  dns.ClassINET,
			Rrtype: dns.TypeTXT,
		}
		for _, cert := range certs {
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
	})
	dns.HandleFunc(".", func(w dns.ResponseWriter, msg *dns.Msg) {
		resp := &dns.Msg{}
		resp.SetReply(msg)
		hdr := dns.RR_Header{
			Name:   msg.Question[0].Name,
			Ttl:    3600,
			Class:  dns.ClassINET,
			Rrtype: dns.TypeA,
		}
		resp.Answer = append(resp.Answer, &dns.A{Hdr: hdr, A: net.IPv4(8, 8, 8, 8)})
		w.WriteMsg(resp)
	})
	fmt.Println(srv.ListenAndServe())
}
