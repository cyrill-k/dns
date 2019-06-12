package pila

// how to call all tests + benchmarks: go test -bench=.

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cyrill-k/dns"
	"github.com/scionproto/scion/go/lib/crypto/cert"
)

const (
	TEST_EXIT_CODE_EXCHANGE_FAILED     = 2
	TEST_EXIT_CODE_VERIFICATION_FAILED = 3
)

const (
	CLIENT_REQUEST_GENERATION             = iota
	CLIENT_CERTIFICATE_CHAIN_VERIFICATION = iota
	CLIENT_VERIFICATION                   = iota
	CLIENT_RESPONSE_PARSING               = iota
	SERVER_CERTIFICATE_RETRIEVAL          = iota
	SERVER_CERTIFICATE_GENERATION         = iota
	SERVER_REQUEST_PARSING                = iota
	SERVER_SIGNATURE                      = iota
	SERVER_RESPONSE_GENERATION            = iota
	ECDSA_SIGN                            = iota
	ECDSA_VERIFY                          = iota

	SERVER_SIGNATURE_AND_RESPONSE_GENERATION_AND_CERTIFICATE_RETRIEVAL = iota

	CLIENT_RESPONSE_PARSING_AND_VERIFICATION = iota
)

const (
	CRYPTO_ALGORITHM_ECDSAP256 = iota
	CRYPTO_ALGORITHM_ECDSAP384 = iota
)

var (
	verification = flag.Bool("verification", false, "run PILA verification tests")
	scionDir     = flag.String("scion", "/home/cyrill/go/src/github.com/scionproto/scion", "Scion start script folder (must contain scion.sh)")
	pilaServer   = flag.String("server", "/home/cyrill/go/src/github.com/cyrill-k/dns/pila/server", "PILA GO client folder")
	pilaClient   = flag.String("client", "/home/cyrill/go/src/github.com/cyrill-k/dns/pila/client", "PILA GO server folder")

	records = map[string]string{
		"test.service.": "1.2.3.4",
	}
)

func BenchmarkAll(b *testing.B) {
	ecdsaAlgs := map[int]string{CRYPTO_ALGORITHM_ECDSAP256: "ECDSAP256", CRYPTO_ALGORITHM_ECDSAP384: "ECDSAP384"}
	ecdsaModes := map[int]string{ECDSA_SIGN: "ECDSA_SIGN", ECDSA_VERIFY: "ECDSA_VERIFY"}
	for algIdx, alg := range ecdsaAlgs {
		for modeIdx, mode := range ecdsaModes {
			b.Run(fmt.Sprintf("%s %s", mode, alg), func(bRun *testing.B) { benchmarkEcdsa(bRun, modeIdx, algIdx) })
		}
	}

	serverModes := map[int]string{
		SERVER_CERTIFICATE_RETRIEVAL: "SERVER_CERTIFICATE_RETRIEVAL",
		SERVER_REQUEST_PARSING:       "SERVER_REQUEST_PARSING",
		//SERVER_RESPONSE_GENERATION:   "SERVER_RESPONSE_GENERATION", around 160ns but takes a long time to finish due to large constant factors so I removed it from the tests
		SERVER_SIGNATURE: "SERVER_SIGNATURE",
		SERVER_SIGNATURE_AND_RESPONSE_GENERATION_AND_CERTIFICATE_RETRIEVAL: "SERVER_TOTAL"}
	serverAlgs := map[int]string{CRYPTO_ALGORITHM_ECDSAP256: "ECDSAP256", CRYPTO_ALGORITHM_ECDSAP384: "ECDSAP384"}
	for algIdx, alg := range serverAlgs {
		for modeIdx, mode := range serverModes {
			b.Run(fmt.Sprintf("%s %s", mode, alg), func(bRun *testing.B) { benchmarkPilaServerSign(bRun, modeIdx, algIdx) })
		}
	}

	clientModes := map[int]string{
		CLIENT_REQUEST_GENERATION: "CLIENT_REQUEST_GENERATION",
		CLIENT_VERIFICATION:       "CLIENT_VERIFICATION",
		// CLIENT_RESPONSE_PARSING:               "CLIENT_RESPONSE_PARSING",
		CLIENT_CERTIFICATE_CHAIN_VERIFICATION: "CLIENT_CERTIFICATE_CHAIN_VERIFICATION",
	}
	clientAlgs := map[int]string{CRYPTO_ALGORITHM_ECDSAP256: "ECDSAP256", CRYPTO_ALGORITHM_ECDSAP384: "ECDSAP384"}
	for algIdx, alg := range clientAlgs {
		for modeIdx, mode := range clientModes {
			b.Run(fmt.Sprintf("%s %s", mode, alg), func(bRun *testing.B) { benchmarkPilaClientVerify(bRun, modeIdx, algIdx) })
		}
	}
}

func benchmarkGeneratePrivateKeyAndHasher(cryptoAlgorithm int) (SignerWithAlgorithm, crypto.Hash) {
	if cryptoAlgorithm == CRYPTO_ALGORITHM_ECDSAP256 {
		privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		signer := NewECDSASigner(privateKey)
		return signer, crypto.SHA256
	} else if cryptoAlgorithm == CRYPTO_ALGORITHM_ECDSAP384 {
		privateKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		signer := NewECDSASigner(privateKey)
		return signer, crypto.SHA384
	} else {
		return nil, crypto.Hash(0)
	}
}

func benchmarkEcdsa(b *testing.B, bt int, cryptoAlgorithm int) {
	// setup
	b.StopTimer()
	signer, hash := benchmarkGeneratePrivateKeyAndHasher(cryptoAlgorithm)

	for i := 0; i < b.N; i++ {
		// create fake content
		content := make([]byte, 1631)
		rand.Read(content)

		// perform signature
		hasher := hash.New()
		hasher.Write(content)

		if bt == ECDSA_SIGN {
			b.StartTimer()
		}
		sig, err := u.Sign(signer.Signer(), hasher.Sum(nil), hash, signer.Algorithm())
		if err != nil {
			b.Errorf("Error creating ECDSA signatures: %s", err.Error())
		}
		if bt == ECDSA_SIGN {
			b.StopTimer()
		}

		// perform verification
		hasher = hash.New()
		hasher.Write(content)
		r := big.NewInt(0)
		r.SetBytes(sig[:len(sig)/2])
		s := big.NewInt(0)
		s.SetBytes(sig[len(sig)/2:])
		ecdsaPubKey := signer.Signer().Public().(*ecdsa.PublicKey)

		if bt == ECDSA_VERIFY {
			b.StartTimer()
		}
		if !ecdsa.Verify(ecdsaPubKey, hasher.Sum(nil), r, s) {
			b.Error("could not verify signature")
		}
		if bt == ECDSA_VERIFY {
			b.StopTimer()
		}

	}
}

func benchmarkPilaServerSign(b *testing.B, bt int, cryptoAlgorithm int) {
	// Generate Server State
	b.StopTimer()

	// disable logging
	log.SetFlags(0)
	log.SetOutput(ioutil.Discard)

	// Create default PILA config
	config := DefaultConfig()
	config.InitializeEnvironment()

	var signer SignerWithAlgorithm
	var chain *cert.PilaChain
	if bt == SERVER_CERTIFICATE_RETRIEVAL {
		signer, _ = benchmarkGeneratePrivateKeyAndHasher(cryptoAlgorithm)
	} else {
		if cryptoAlgorithm == CRYPTO_ALGORITHM_ECDSAP256 {
			var priv *ecdsa.PrivateKey
			priv, _, chain, _, _ = ReadP256Config()
			signer = NewECDSASigner(priv)
		} else if cryptoAlgorithm == CRYPTO_ALGORITHM_ECDSAP384 {
			var priv *ecdsa.PrivateKey
			priv, _, chain, _, _ = ReadP384Config()
			signer = NewECDSASigner(priv)
		} else {
			b.Error("Unsupported crypto algorithm")
		}
	}

	// Generate request
	req := new(dns.Msg)
	req.SetQuestion("test.service.", dns.TypeA)
	config.PilaRequestSignature(req)

	if bt == SERVER_SIGNATURE_AND_RESPONSE_GENERATION_AND_CERTIFICATE_RETRIEVAL {
		b.StartTimer()
	}
	for i := 0; i < b.N; i++ {
		if bt == SERVER_CERTIFICATE_RETRIEVAL {
			b.StartTimer()

			asCertificateHandler := NewASCertificateHandler(&config)
			// Extract public key
			pub, err := GetPublicKeyWithAlgorithm(signer)
			if err != nil {
				b.Errorf("Failed to extract public key to send to the certificate server: " + err.Error())
			}
			chain, err = asCertificateHandler.PilaRequestASCertificate(pub)
			if err != nil {
				b.Errorf("Failed to request PilaChain: " + err.Error())
			}

			b.StopTimer()
			continue
		}

		if bt == SERVER_RESPONSE_GENERATION {
			b.StartTimer()
		}

		// Prepare response
		response := new(dns.Msg)
		response.SetReply(req)
		response.Compress = false

		if bt == SERVER_RESPONSE_GENERATION {
			b.StopTimer()
			continue
		}

		if bt == SERVER_REQUEST_PARSING {
			b.StartTimer()
		}

		benchmarkParseQuery(response)

		if bt == SERVER_REQUEST_PARSING {
			b.StopTimer()
			continue
		}

		if bt == SERVER_SIGNATURE {
			b.StartTimer()
		}

		// Sign response
		host := "127.0.0.1"
		var packedOriginalMessage []byte
		req.PackBuffer(packedOriginalMessage)
		if err := config.PilaSign(response, packedOriginalMessage, signer, net.ParseIP(host), PostSignNoOp, chain); err != nil {
			b.Errorf("[SERVER DEBUG] Error in PilaSign: %s", err.Error())
		}

		if bt == SERVER_SIGNATURE {
			b.StopTimer()
		}
	}

	// if err := config.PilaVerify(response, packedOriginalMessage, net.ParseIP(host)); err != nil {
	// 	log.Println("[SERVER DEBUG] Error in PilaVerify: " + err.Error())
	// }
}

func benchmarkGenerateRequestResponsePair(b *testing.B, config *PilaConfig, signer SignerWithAlgorithm, chain *cert.PilaChain) (request *dns.Msg, response *dns.Msg) {
	request = new(dns.Msg)
	request.SetQuestion("test.service.", dns.TypeA)
	config.PilaRequestSignature(request)

	response = request.Copy()
	response.SetReply(request)
	response.Compress = false
	benchmarkParseQuery(response)

	requestPacked, _ := request.Pack()
	err := config.PilaSign(response, requestPacked, signer, net.ParseIP("127.0.0.1"), PostSignNoOp, chain)
	if err != nil {
		b.Errorf("Could not sign request: %s\n", err.Error())
	}
	return
}

func benchmarkPilaClientVerify(b *testing.B, bt int, cryptoAlgorithm int) {
	// Generate Server State
	b.StopTimer()

	// disable logging
	log.SetFlags(0)
	log.SetOutput(ioutil.Discard)
	// enable logging
	// log.SetFlags(log.LstdFlags)
	// log.SetOutput(os.Stdout)

	// Create default PILA config
	config := DefaultConfig()
	config.InitializeEnvironment()

	var signer SignerWithAlgorithm
	var chain *cert.PilaChain
	if cryptoAlgorithm == CRYPTO_ALGORITHM_ECDSAP256 {
		var priv *ecdsa.PrivateKey
		priv, _, chain, _, _ = ReadP256Config()
		signer = NewECDSASigner(priv)
	} else if cryptoAlgorithm == CRYPTO_ALGORITHM_ECDSAP384 {
		var priv *ecdsa.PrivateKey
		priv, _, chain, _, _ = ReadP384Config()
		signer = NewECDSASigner(priv)
	} else {
		b.Error("Unsupported crypto algorithm")
	}

	request, response := benchmarkGenerateRequestResponsePair(b, &config, signer, chain)

	// Read original message and signed message
	packedOriginalMessage, err := request.Pack()
	if err != nil {
		b.Error("Error packing original message: " + err.Error())
	}
	m := response
	localIp := net.ParseIP("127.0.0.1")

	for i := 0; i < b.N; i++ {
		if bt == CLIENT_REQUEST_GENERATION {
			b.StartTimer()
		}
		// Retrieve (PILA) SIG record from message
		sigrr, err := getPilaSIG(m)
		if err != nil {
			b.Error("Error reading last SIG record from dns message: " + err.Error())
		}
		if sigrr == nil {
			b.Error("No PILA SIG record available")
		}

		// extract TXT record containing the certificate chain
		pilaTxt, err := getPilaTxtRecord(m)
		if err != nil {
			b.Error("Failed to decode PILA TXT record: " + err.Error())
		}

		// extract the certificate chain
		pilaChain, err := cert.PilaChainFromRaw(pilaTxt.CertificateChainRaw)
		if err != nil {
			b.Error("Failed to parse PILA certificate chain: " + err.Error())
		}

		if bt == CLIENT_REQUEST_GENERATION {
			b.StopTimer()
			continue
		}

		if bt == CLIENT_CERTIFICATE_CHAIN_VERIFICATION {
			b.StartTimer()
		}

		// verify certificate chain using locally stored trc
		trc, err := config.readTrc()
		if err := pilaChain.Verify(cert.PilaCertificateEntity{Ipv4: localIp}, trc); err != nil {
			b.Error("Failed to verify PILA certificate chain: " + err.Error())
		}

		if bt == CLIENT_CERTIFICATE_CHAIN_VERIFICATION {
			b.StopTimer()
		}

		if bt == CLIENT_VERIFICATION {
			b.StartTimer()
		}

		// get public key from leaf cert and set corresponding algorithm & base64 pubkey
		var algorithm uint8
		switch pilaChain.Endpoint.SignAlgorithm {
		case "ECDSAP256SHA256":
			algorithm = dns.ECDSAP256SHA256
		case "ECDSAP384SHA384":
			algorithm = dns.ECDSAP384SHA384
		default:
			b.Error("Unsupported signing algorithm in endpoint certificate: " + pilaChain.Endpoint.SignAlgorithm)
		}
		pubKeyBase64 := u.ToBase64(pilaChain.Endpoint.SubjectSignKey)

		// Create verification context based on original message & local endpoint identifier
		additionalInfo, err := getAdditionalInfo(sigrr, packedOriginalMessage, encode(localIp))
		if err != nil {
			b.Error("Failed to extract additional info from request")
		}

		// Create dns.KEY object to verify signature
		key := createPilaKEY(3, algorithm, pubKeyBase64)

		// Verify signature
		buf, err := m.Pack()
		if err != nil {
			b.Error("Failed to pack message: " + err.Error())
		}
		// log.Printf("****************** sigrr = \n\n%+v\n\n", sigrr)
		// log.Printf("****************** key = \n\n%+v\n\n", key)
		// log.Printf("****************** buf = \n\n%+v\n\n", buf)
		// log.Printf("****************** additionalInfo = \n\n%+v\n\n", additionalInfo)
		err = pilaVerifyRR(sigrr, key, buf, additionalInfo)
		if err != nil {
			b.Errorf("Failed to verify RR: %s\n", err.Error())
		}

		if bt == CLIENT_VERIFICATION {
			b.StopTimer()
		}
	}
}

func benchmarkParseQuery(m *dns.Msg) {
	for _, q := range m.Question {
		switch q.Qtype {
		case dns.TypeA:
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

// -------------------------------------------------------------------------------------------------------------------

func TestPilaSign(t *testing.T) {
	// Test successful signing
	ret, err := testClientVerification(t, "", true)
	if err != nil {
		t.Fatalf("Successful signing test failed with: %s", err.Error())
	} else {
		if ret != 0 {
			t.Fatalf("Non-zero return value but no error!")
		}
	}
}

func TestPilaVerify(t *testing.T) {
	// Test successful verification
	ret, err := testClientVerification(t, "-randomsig", true)
	if err == nil {
		t.Fatalf("Fake signature was accepted by client")
	} else {
		if ret != TEST_EXIT_CODE_VERIFICATION_FAILED {
			t.Fatalf("Other error than fake signature detected: " + err.Error())
		}
	}
}

func testBuildGoSource(goExecutablePath string, goSourcePath string) error {
	err := testGetCmd([]string{"go", "build", "-o", goExecutablePath, goSourcePath}).Run()
	if err != nil {
		return fmt.Errorf("Error building (%s): %s", goSourcePath, err.Error())
	}
	return nil
}

func testGetCmd(args []string) *exec.Cmd {
	if len(args) == 0 {
		panic("Executing empty argument list")
	}
	var b strings.Builder
	b.Write([]byte("Executing: "))
	for i, s := range args {
		if i != 0 {
			b.Write([]byte(" "))
		}
		b.Write([]byte(s))
	}
	log.Println(b.String())
	return exec.Command(args[0], args[1:]...)
}

func testClientVerification(t *testing.T, serverFlag string, debug bool) (ret int, err error) {
	// Starting SCION
	scionCmd := testGetCmd([]string{"/bin/bash", "scion.sh", "start"})
	scionCmd.Dir = *scionDir
	if debug {
		scionCmd.Stdout = os.Stdout
		scionCmd.Stderr = os.Stderr
	}
	err = scionCmd.Run()
	if err != nil {
		err = fmt.Errorf("scion script failed: %s", err.Error())
		ret, _ = testGetErrorCode(err)
		return
	}

	// Build PILA client
	goClientPath := path.Join(*pilaClient, "main.go")
	goClientExePath := path.Join(*pilaClient, "main")
	err = testBuildGoSource(goClientExePath, goClientPath)
	if err != nil {
		return
	}

	f, err := testStartServer(serverFlag, debug)
	if f != nil {
		defer f()
	}
	if err != nil {
		return
	}

	// Start PILA client
	goClient := testGetCmd([]string{goClientExePath})
	if debug {
		goClient.Stdout = os.Stdout
		goClient.Stderr = os.Stderr
	}
	err = goClient.Run()
	if err != nil {
		ret, _ = testGetErrorCode(err)
		err = fmt.Errorf("Error executing the go client: %s\n", err.Error())
	}
	return
}

// Opens an instance of a PILA server and returns err = nil if the server is listening and ready to accept requests or a non-nil error describing the error that occurred. If the process has not exited when the function returns, f contains a clean up function for the server and its children.
func testStartServer(serverFlag string, debug bool) (cleanUp func(), err error) {
	// Build PILA server
	goServerPath := path.Join(*pilaServer, "main.go")
	goServerExePath := path.Join(*pilaServer, "main")
	err = testBuildGoSource(goServerExePath, goServerPath)
	if err != nil {
		return
	}

	// Start PILA server in background
	var goServer *exec.Cmd
	if serverFlag == "" {
		goServer = testGetCmd([]string{goServerExePath})
	} else {
		goServer = testGetCmd([]string{goServerExePath, serverFlag})
	}
	if debug {
		//goServer.Stdout = os.Stdout
		goServer.Stderr = os.Stderr
	}

	// allow killing process spawned by goServer process
	testAllowProcessKill(goServer)

	// pass clean up function to caller
	cleanUp = func() {
		log.Printf("Cleaning up the go server...")
		testKillProcess(goServer.Process)
	}

	// Get stdout reader
	serverReader, err := goServer.StdoutPipe()
	if err != nil {
		err = errors.New("Error getting stdout pipe: " + err.Error())
		return
	}

	// Start server
	err = goServer.Start()
	if err != nil {
		return
	}

	// Read until a line beginning with "Listening at " is read
	serverScanner := bufio.NewScanner(serverReader)
	serverError := make(chan error, 1)
	go func() {
		for serverScanner.Scan() {
			log.Println("[Server stdout]: " + serverScanner.Text())
			if strings.Contains(serverScanner.Text(), "Listening at ") {
				serverError <- nil
				return
			}
		}
		if serverScanner.Err() == nil {
			serverError <- errors.New("Scanner reached EOF (Server process probably quit)")
		} else {
			serverError <- serverScanner.Err()
		}
	}()

	// Wait for timeout or error
	select {
	case err = <-serverError:
		if err != nil {
			err = fmt.Errorf("Server could not be started: %v", err.Error())
		}
	case <-time.After(2 * time.Second):
		err = fmt.Errorf("Timeout waiting for server to start")
	}

	return
}

// allow killing process spawned by this command
func testAllowProcessKill(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// Kill p and processes spawned by it (testAllowProcessKill should be called in advance)
func testKillProcess(p *os.Process) {
	pgid, err := syscall.Getpgid(p.Pid)
	if err == nil {
		syscall.Kill(-pgid, 15) // note the minus sign
	}
}

func testGetErrorCode(err error) (ret int, retFound bool) {
	if exiterr, ok := err.(*exec.ExitError); ok {
		if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
			ret = status.ExitStatus()
			retFound = true
		}
	}
	return
}
