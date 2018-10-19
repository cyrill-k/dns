package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"strconv"

	"github.com/cyrill-k/dns"
)

var records = map[string]string{
	"test.service.": "192.168.0.2",
}

func parseQuery(m *dns.Msg) {
	for _, q := range m.Question {
		switch q.Qtype {
		case dns.TypeA:
			log.Printf("Query for %s\n", q.Name)
			ip := records[q.Name]
			if ip != "" {
				rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, ip))
				if err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
		}
	}
}

func handleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		parseQuery(m)
	}

	w.WriteMsg(m)
}

type ClientConfig struct {
	LocalPort  uint16
	LocalIP    net.IP
	RemotePort uint16
	RemoteIP   net.IP
}

func main() {
	// // version 1) vendor/x
	// buf := make([]byte, 2, 514)
	// b := NewBuilder(buf, Header{})
	// // b.EnableCompression()
	// // Optionally start a section and add things to that section.
	// // Repeat adding sections as necessary.
	// b.StartQuestions()
	// buf, err := b.Finish()

	// version 2)
	//c := new(dns.Client)
	//c.TsigSecret = map[string]string{"axfr.": "so6ZGir4GPAqINNh9U5c3A=="}
	//m := new(dns.Msg)
	//m.SetQuestion("test.service.", dns.TypeA)
	//dns.PilaRequestSignature(m)
	//m.SetTsig("axfr.", dns.HmacMD5, 300, time.Now().Unix())

	// process CLI argument
	var config ClientConfig
	config.RemoteIP = net.ParseIP(*flag.String("remoteip", "127.0.0.1", "Server IP address"))
	config.LocalIP = net.ParseIP(*flag.String("localip", "127.0.0.1", "Client IP address"))
	config.RemotePort = uint16(*flag.Uint("remoteport", 7501, "Server IP address"))
	//config.RemoteIP = *flag.Uint("localport", "127.0.0.1", "Server IP address")
	keyFolder := flag.String("genfolder", "-", "folder where the ECDSA keys are saved")
	flag.Parse()
	if *keyFolder == "-" {
		*keyFolder = "/home/cyrill/test/"
	}
	privPath := filepath.Join(*keyFolder, "private.pem")
	pubPath := filepath.Join(*keyFolder, "public.pem")

	_, pub := dns.ReadKeys(privPath, pubPath)
	verifier := dns.NewECDSAPublicKey(pub)

	m := new(dns.Msg)
	m.SetQuestion("test.service.", dns.TypeA)
	dns.PilaRequestSignature(m)

	// start client
	c := new(dns.Client)

	// perform exchange
	in, _, err := c.Exchange(m, config.RemoteIP.String()+":"+strconv.FormatUint(uint64(config.RemotePort), 10))
	if err != nil {
		log.Fatalf("Failed to exchange message: %s\n ", err.Error())
	}

	log.Println("test3")

	// verify signature
	err = dns.PilaVerify(in, m, verifier, config.LocalIP)
	if err != nil {
		log.Fatalf("PILA verification failed: %s", err.Error())
	}

	log.Printf("Response: %s\n", in.String())
}
