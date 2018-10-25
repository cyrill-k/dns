package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
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

var config dns.PilaConfig

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

	error = config.PilaSign(m, signer, net.ParseIP(host))
	if error != nil {
		log.Printf("Error signing response: ", error.Error())
	}

	w.WriteMsg(m)
}

func main() {
	generateKeys := flag.Bool("gen", false, "generate new public/private ECDSA keys")
	keyFolder := flag.String("genfolder", "-", "folder where the ECDSA keys are saved")
	debugFlag := flag.Bool("debug", false, "Enable debug mode")
	testingFlag := flag.Bool("test", false, "Enable testing mode")
	flag.Parse()

	config = dns.DefaultConfig()

	if *keyFolder == "-" {
		*keyFolder = "/home/cyrill/test/"
	}
	privPath := filepath.Join(*keyFolder, "private.pem")
	pubPath := filepath.Join(*keyFolder, "public.pem")

	if *generateKeys {
		privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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
	signer = dns.NewECDSASigner(priv)

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
		if error := config.PilaSign(response, signer, net.ParseIP(host)); error != nil {
			log.Println("Error in PilaSign: " + error.Error())
		}
		dns.DebugPrint("response2", response)

		if error := config.PilaVerify(response, req, verifier, net.ParseIP(host)); error != nil {
			log.Println("Error in PilaVerify: " + error.Error())
		}
		dns.DebugPrint("response3", response)

		//TODO: write tests

		return
	}

	if *testingFlag {
		s := &S{Ivalue: &Impl1{val: "test"}}
		marshalled, err := json.Marshal(s)
		if err != nil {
			panic(err.Error())
		}
		log.Println(string(marshalled))
		sNew := &S{}
		err = json.Unmarshal(marshalled, sNew)
		if err != nil {
			panic(err.Error())
		}
		log.Println("val = " + sNew.Ivalue.f())

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

type I interface {
	MarshalText() ([]byte, error)
	UnmarshalText(text []byte) error
	f() string
}

const (
	type1 uint8 = 7
	type2 uint8 = 42
)

type Istruct struct {
	typeFieldHidden uint8
	impl            I
}

func (i Istruct) MarshalText() ([]byte, error) {
	return i.MarshalText()
}

type Impl1 struct {
	Istruct
	val string
}

func (impl Impl1) MarshalText() ([]byte, error) {
	return []byte(impl.val), nil
}

func (impl *Impl1) UnmarshalText(text []byte) error {
	impl.val = string(text)
	return nil
}

func (impl Impl1) f() string {
	return impl.val
}

type S struct {
	Ivalue *Impl1
}
