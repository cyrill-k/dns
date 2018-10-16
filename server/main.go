package main

import (
	"flag"
	"fmt"
	"log"
	"path/filepath"
	"strconv"

	"github.com/cyrill-k/dns"
)

var records = map[string]string{
	"test.service.": "1.2.3.4",
}

var keys = map[string]string{}

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

	pilaSign(m, keys["private"])

	w.WriteMsg(m)
}

func main() {
	generateKeys := flag.Bool("gen", false, "generate new public/private ECDSA keys")
	keyFolder := flag.String("genfolder", "-", "folder where the ECDSA keys are saved")
	flag.Parse()

	if keyFolder == "-" {
		keyFolder = "~/test/"
	}
	privPath := filepath.Join(keyFolder, "private.pem")
	pubPath := filepath.Join(keyFolder, "public.pem")

	if generateKeys {
		privateKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		publicKey := &privateKey.PublicKey

		encPriv, encPub := encode(privateKey, publicKey)

		err = ioutil.WriteFile(privPath, []byte(encPriv), 0644)
		if err != nil {
			panic(err)
		}
		err = ioutil.WriteFile(pubPath, []byte(encPub), 0644)
		if err != nil {
			panic(err)
		}
	}

	priv, pub := readKeys(privPath, pubPath)
	keys["private"] = priv
	keys["public"] = pub

	// attach request handler func
	dns.HandleFunc("service.", handleDnsRequest)

	// start server
	port := 7501
	server := &dns.Server{Addr: ":" + strconv.Itoa(port), Net: "udp"}
	log.Printf("Starting at %d\n", port)
	err := server.ListenAndServe()
	defer server.Shutdown()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}
}
