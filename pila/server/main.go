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
	"os"
	"path/filepath"
	"strconv"

	"github.com/cyrill-k/dns"
	"github.com/cyrill-k/dns/pila"

	"github.com/scionproto/scion/go/lib/crypto/cert"
)

var (
	records = map[string]string{
		"test.service.": "1.2.3.4",
	}

	generateKeys       = flag.Bool("gen", false, "generate new public/private ECDSA keys")
	keyFolder          = flag.String("keyfolder", "-", "Read ECDSA keys from folder (priv.pem & pub.pem)")
	pilaChainPath      = flag.String("pilachain", "-", "Path of the PILA certificate chain (e.g., \"pilachain\")")
	debugFlag          = flag.Bool("debug", false, "Enable debug mode")
	randomsigFlag      = flag.Bool("randomsig", false, "Replace signature in the PILA SIG record with random data")
	disableLoggingFlag = flag.Bool("disable-logging", false, "Disable message logging")

	signer pila.SignerWithAlgorithm

	config pila.PilaConfig
)

func parseQuery(m *dns.Msg) {
	for _, q := range m.Question {
		switch q.Qtype {
		case dns.TypeA:
			log.Printf("[Server] Query for %s\n", q.Name)
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
	log.Printf("[Server] Received request (id=%d)\n", r.Id)
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		parseQuery(m)
	}

	host, _, err := net.SplitHostPort(w.RemoteAddr().String())
	if err != nil {
		log.Printf("[Server] Error retrieving IP address: %s", err.Error())
		return
	}

	packedOriginalMessage, err := r.Pack()
	if err != nil {
		log.Printf("[Server] Failed to pack request into buffer: %s\n ", err.Error())
		os.Exit(pila.EXIT_CODE_INTERNAL_ERROR)
	}
	var chain *cert.PilaChain
	if *pilaChainPath != "-" {
		chain, err = pila.ReadPilaCertificateChain(*pilaChainPath)
		if err != nil {
			log.Printf("[Server] Error reading pila certificate chain from file (%s): %s", *pilaChainPath, err.Error())
			return
		}
	}
	if *randomsigFlag {
		// Replace signature with a random value of the same length
		err = config.PilaSign(m, packedOriginalMessage, signer, net.ParseIP(host),
			func(in []byte) []byte {
				r, _ := pila.GenerateRandomness(len(in))
				return r
			}, chain)
	} else {
		err = config.PilaSign(m, packedOriginalMessage, signer, net.ParseIP(host), pila.PostSignNoOp, chain)
	}
	if err != nil {
		log.Printf("[Server] Error signing response: " + err.Error())
		return
	}

	log.Printf("[Server]: Sending reply (id=%d)\n", m.Id)
	w.WriteMsg(m)
}

func main() {
	// Parse CLI
	flag.Parse()

	if *disableLoggingFlag {
		log.SetFlags(0)
		log.SetOutput(ioutil.Discard)
	}

	// Create default PILA config
	config = pila.DefaultConfig()
	config.InitializeEnvironment()

	if *keyFolder == "-" {
		*keyFolder = "/home/cyrill/test/"
	}
	privPath := filepath.Join(*keyFolder, "priv.pem")
	pubPath := filepath.Join(*keyFolder, "pub.pem")

	if *generateKeys {
		privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		publicKey := privateKey.PublicKey

		encPriv, encPub := pila.EncodeEcdsaKeys(privateKey, &publicKey)

		err := ioutil.WriteFile(privPath, encPriv, 0644)
		if err != nil {
			panic(err)
		}
		err = ioutil.WriteFile(pubPath, encPub, 0644)
		if err != nil {
			panic(err)
		}
	}

	priv, _ := pila.ReadKeys(privPath, pubPath)
	if priv == nil {
		log.Fatalf("[Server] Failed to read private key from file (%s)\n", privPath)
	}
	signer = pila.NewECDSASigner(priv)

	if *debugFlag {
		req := new(dns.Msg)
		req.SetQuestion("test.service.", dns.TypeA)
		config.PilaRequestSignature(req)

		response := req.Copy()
		response.SetReply(req)
		response.Compress = false
		parseQuery(response)

		host := "127.0.0.1"
		var packedOriginalMessage []byte
		req.PackBuffer(packedOriginalMessage)
		if err := config.PilaSign(response, packedOriginalMessage, signer, net.ParseIP(host), pila.PostSignNoOp, nil); err != nil {
			log.Println("[SERVER DEBUG] Error in PilaSign: " + err.Error())
		}

		if err := config.PilaVerify(response, packedOriginalMessage, net.ParseIP(host)); err != nil {
			log.Println("[SERVER DEBUG] Error in PilaVerify: " + err.Error())
		}

		return
	}

	// attach request handler func
	dns.HandleFunc("service.", handleDnsRequest)

	// start server
	port := 7501
	server := &dns.Server{Addr: ":" + strconv.Itoa(port), Net: "udp", NotifyStartedFunc: func() { fmt.Printf("[Server] Listening at %d\n", port) }}
	log.Printf("[Server] Starting at %d\n", port)
	err := server.ListenAndServe()
	defer server.Shutdown()
	if err != nil {
		log.Fatalf("[Server] Failed to start server: %s\n ", err.Error())
	}
}
