package pila

// how to call all tests + benchmarks: go test -bench=.

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
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
	CLIENT_REQUEST_GENERATION    = iota
	CLIENT_VERIFICATION          = iota
	CLIENT_RESPONSE_PARSING      = iota
	SERVER_CERTIFICATE_RETRIEVAL = iota
	SERVER_REQUEST_PARSING       = iota
	SERVER_SIGNATURE             = iota
	SERVER_RESPONSE_GENERATION   = iota

	SERVER_SIGNATURE_AND_RESPONSE_GENERATION_AND_CERTIFICATE_RETRIEVAL = iota

	CLIENT_RESPONSE_PARSING_AND_VERIFICATION = iota
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

// func BenchmarkPilaClientRequestGeneration(b *testing.B) {
// 	benchmarkPilaServerSign(b, CLIENT_REQUEST_GENERATION)
// }
// func BenchmarkPilaClientVerification(b *testing.B) {
// 	benchmarkPilaServerSign(b, CLIENT_VERIFICATION)
// }
// func BenchmarkPilaClientResponseParsing(b *testing.B) {
// 	benchmarkPilaServerSign(b, CLIENT_RESPONSE_PARSING)
// }

func BenchmarkPilaServerCertificateRetrieval(b *testing.B) {
	benchmarkPilaServerSign(b, SERVER_CERTIFICATE_RETRIEVAL)
}
func BenchmarkPilaServerRequestParsing(b *testing.B) {
	benchmarkPilaServerSign(b, SERVER_REQUEST_PARSING)
}
func BenchmarkPilaServerSignature(b *testing.B) {
	benchmarkPilaServerSign(b, SERVER_SIGNATURE)
}
func BenchmarkPilaServerResponseGeneration(b *testing.B) {
	benchmarkPilaServerSign(b, SERVER_RESPONSE_GENERATION)
}
func BenchmarkPilaServerTotalResponseTime(b *testing.B) {
	benchmarkPilaServerSign(b, SERVER_SIGNATURE_AND_RESPONSE_GENERATION_AND_CERTIFICATE_RETRIEVAL)
}

// func BenchmarkPilaClientTotalVerificationTime(b *testing.B) {
// 	benchmarkPilaServerSign(b, CLIENT_RESPONSE_PARSING_AND_VERIFICATION)
// }

func benchmarkPilaServerSign(b *testing.B, bt int) {
	// Generate Server State
	b.StopTimer()

	// disable logging
	log.SetFlags(0)
	log.SetOutput(ioutil.Discard)

	// Create default PILA config
	config := DefaultConfig()
	config.InitializeEnvironment()

	// Private keys
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer := NewECDSASigner(privateKey)

	// Generate request
	req := new(dns.Msg)
	req.SetQuestion("test.service.", dns.TypeA)
	config.PilaRequestSignature(req)

	if bt == SERVER_SIGNATURE_AND_RESPONSE_GENERATION_AND_CERTIFICATE_RETRIEVAL {
		b.StartTimer()
	}
	for i := 0; i < b.N; i++ {

		if bt == SERVER_RESPONSE_GENERATION {
			b.StartTimer()
		}

		// Prepare response
		response := new(dns.Msg)
		response.SetReply(req)
		response.Compress = false

		if bt == SERVER_RESPONSE_GENERATION {
			b.StopTimer()
		}

		if bt == SERVER_REQUEST_PARSING {
			b.StartTimer()
		}

		benchmarkParseQuery(response)

		if bt == SERVER_REQUEST_PARSING {
			b.StopTimer()
		}

		if bt == SERVER_SIGNATURE {
			b.StartTimer()
		}

		// Sign response
		host := "127.0.0.1"
		var packedOriginalMessage []byte
		req.PackBuffer(packedOriginalMessage)

		if bt == SERVER_SIGNATURE {
			b.StopTimer()
		}

		var chain *cert.PilaChain
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
		} else {
			chainJsonStringRepresentation := `{"0":{"CanIssue":false,"Comment":"PILA CERTIFICATE","EncAlgorithm":"","ExpirationTime":1559926075,"Issuer":"17-1039","IssuingTime":1559922475,"SignAlgorithm":"ECDSAP384SHA384","Signature":"9I8Ra/VXfy9HNapXj26vhqALuHAs2XjbSdYXiVwNvjdrR142cVleI2ntlSAVdrsPy8UfLOBKXxwua+uz040iBQ==","Subject":"127.0.0.1","SubjectEncKey":null,"SubjectSignKey":"Zn8z4FyIrDMX31cxeCKy2tJ3+0yGdEQ41fgLUzP+oOSGc2RISocemuWqM1koOwAOWtK2PAyQqvkjtFn7f39DDyLQgFY9ikRp2esnSl0xwgSg2xEBTMrtnOLOZUFUbArJ","TRCVersion":1,"Version":1},"1":{"CanIssue":false,"Comment":"AS Certificate","EncAlgorithm":"curve25519xsalsa20poly1305","ExpirationTime":1561474358,"Issuer":"17-ffaa:0:1101","IssuingTime":1539093902,"SignAlgorithm":"ed25519","Signature":"h6DjGKY64jqLAUeu/kynyNK/ECFm96aa6GE6hqN6ZZmKnDr7DCA9lTjIZmbpG9bb2IBbc/KbZWPghci8Q7kzAA==","Subject":"17-1039","SubjectEncKey":"oRqsPfh6JecLw02Adu9J25Wy3N/11oOC9uAonDWkqDA=","SubjectSignKey":"imgMPBcP0GPEiDgQZaS4vNrafvCzeTkbI31gcs8c5oc=","TRCVersion":1,"Version":1},"2":{"CanIssue":true,"Comment":"Core AS Certificate","EncAlgorithm":"curve25519xsalsa20poly1305","ExpirationTime":1561474359,"Issuer":"17-ffaa:0:1101","IssuingTime":1530024759,"SignAlgorithm":"ed25519","Signature":"Y8zhfe4nvgX54s8njHojeO2aDYJPE6e5UrgKys/0zF9KJTCW5VwdPTnmx4u5c9BLqxdrj7YKOibbimCAAcmVCQ==","Subject":"17-ffaa:0:1101","SubjectEncKey":"rtCgQv0qyShOol0EW/ULU41qLvqA6urn+C/tHoDwkwY=","SubjectSignKey":"bXbDRwVSWU4YhjE5eSYWWC8AtqG0zyo+8rcsx3p0v6U=","TRCVersion":1,"Version":1}}`
			var err error
			chain, err = cert.PilaChainFromRaw([]byte(chainJsonStringRepresentation))
			if err != nil {
				b.Errorf("Error in unmarshalling pila chain: %s", err.Error())
			}
		}

		if bt == SERVER_SIGNATURE {
			b.StartTimer()
		}

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

func benchmarkParseQuery(m *dns.Msg) {
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
