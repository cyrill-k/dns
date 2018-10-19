package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"path/filepath"
	"strconv"

	"github.com/cyrill-k/dns"
)

var records = map[string]string{
	"test.service.": "1.2.3.4",
}

var signer dns.SignerWithAlgorithm

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

	host, _, error := net.SplitHostPort(w.RemoteAddr().String())
	if error != nil {
		log.Printf("Error retrieving IP address: ", error.Error())
	}

	error = dns.PilaSign(m, signer, net.ParseIP(host))
	if error != nil {
		log.Printf("Error signing response: ", error.Error())
	}

	w.WriteMsg(m)
}

func main() {
	generateKeys := flag.Bool("gen", false, "generate new public/private ECDSA keys")
	keyFolder := flag.String("genfolder", "-", "folder where the ECDSA keys are saved")
	debugFlag := flag.Bool("debug", false, "Enable debug mode")
	flag.Parse()

	if *keyFolder == "-" {
		*keyFolder = "/home/cyrill/test/"
	}
	privPath := filepath.Join(*keyFolder, "private.pem")
	pubPath := filepath.Join(*keyFolder, "public.pem")

	if *generateKeys {
		privateKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		publicKey := privateKey.PublicKey

		encPriv, encPub := dns.EncodeEcdsaKeys(privateKey, &publicKey)

		err := ioutil.WriteFile(privPath, []byte(encPriv), 0644)
		if err != nil {
			panic(err)
		}
		err = ioutil.WriteFile(pubPath, []byte(encPub), 0644)
		if err != nil {
			panic(err)
		}
	}

	priv, _ := dns.ReadKeys(privPath, pubPath)
	signer := dns.NewECDSASigner(priv)

	_, pub := dns.ReadKeys(privPath, pubPath)
	verifier := dns.NewECDSAPublicKey(pub)

	if *debugFlag {
		req := new(dns.Msg)
		req.SetQuestion("test.service.", dns.TypeA)
		dns.DebugPrint("req1", req)
		dns.PilaRequestSignature(req)
		dns.DebugPrint("req2", req)

		response := req.Copy()
		response.SetReply(req)
		response.Compress = false
		parseQuery(response)
		dns.DebugPrint("response1", response)

		host := "127.0.0.1"
		if error := dns.PilaSign(response, signer, net.ParseIP(host)); error != nil {
			log.Println("Error in PilaSign: " + error.Error())
		}
		dns.DebugPrint("response2", response)

		if error := dns.PilaVerify(response, req, verifier, net.ParseIP(host)); error != nil {
			log.Println("Error in PilaVerify: " + error.Error())
		}
		dns.DebugPrint("response3", response)

		return
	}

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
