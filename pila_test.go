package dns

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"syscall"
	"testing"
	"time"
)

const (
	TEST_EXIT_CODE_EXCHANGE_FAILED     = 2
	TEST_EXIT_CODE_VERIFICATION_FAILED = 3
)

var (
	verification = flag.Bool("verification", false, "run PILA verification tests")
	scionDir     = flag.String("scion", "/home/cyrill/go/src/github.com/scionproto/scion", "Scion start script folder (must contain scion.sh)")
	pilaServer   = flag.String("server", "/home/cyrill/go/src/github.com/cyrill-k/dns/server", "PILA GO client folder")
	pilaClient   = flag.String("client", "/home/cyrill/go/src/github.com/cyrill-k/dns/client", "PILA GO server folder")
)

var killHooks []killHook

func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(m.Run())
	log.Printf("Executing %d killHooks\n", len(killHooks))
	for _, h := range killHooks {
		h()
	}
}

func TestPilaSign(t *testing.T) {
	// Test successful signing
	ret, err, f := testClientVerification(t, "", true)
	killHooks = append(killHooks, f)
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
	ret, err, f := testClientVerification(t, "-randomsig", true)
	killHooks = append(killHooks, f)
	if err == nil {
		t.Fatalf("Fake signature was accepted by client")
	} else {
		log.Printf("ret = %d: err = %s\n", ret, err.Error())
		//todo(cyrill): fix collection of error codes
		// if ret != TEST_EXIT_CODE_VERIFICATION_FAILED {
		// 	t.Fatalf("Other error than fake signature detected")
		// }
	}
}

type killHook func()

func testClientVerification(t *testing.T, serverFlag string, debug bool) (ret int, err error, f killHook) {
	// testCmd := exec.Command("/bin/bash", "/home/cyrill/go/src/github.com/cyrill-k/dns/client/s", "start")
	// err = testCmd.Run()
	// if err != nil {
	// 	log.Printf("test script failed: %s", err.Error())
	// 	ret, _ = testGetErrorCode(err)
	// 	return
	// }

	scionCmd := exec.Command("/bin/bash", "scion.sh", "start")
	scionCmd.Dir = *scionDir
	if debug {
		scionCmd.Stdout = os.Stdout
		scionCmd.Stderr = os.Stderr
	}
	err = scionCmd.Run()
	if err != nil {
		log.Printf("scion script failed: %s", err.Error())
		ret, _ = testGetErrorCode(err)
		return
	}

	// // start test go app
	// goTest := exec.Command("go", "run", "/home/cyrill/go/src/github.com/cyrill-k/dns/client/test/output.go")
	// goTest.Stdout = os.Stdout
	// goTest.Stderr = os.Stderr
	// err = goTest.Run()
	// if err != nil {
	// 	// log.Println(out)
	// 	// if exiterr, ok := err.(*exec.ExitError); ok {
	// 	// 	log.Printf("%s\n", string(exiterr.Stderr))
	// 	// }
	// 	ret, _ = testGetErrorCode(err)
	// 	err = fmt.Errorf("Error executing the test go app: %s\n", err.Error())
	// 	return
	// } else {
	// 	log.Println("Successfully ran go test app")
	// 	// log.Println(out)
	// }

	// Start PILA server in background
	var goServer *exec.Cmd
	if serverFlag == "" {
		goServer = exec.Command("go", "run", path.Join(*pilaServer, "main.go"))
	} else {
		goServer = exec.Command("go", "run", path.Join(*pilaServer, "main.go"), serverFlag)
	}
	if debug {
		goServer.Stdout = os.Stdout
		goServer.Stderr = os.Stderr
	}
	err = goServer.Start()
	if err != nil {
		ret, _ = testGetErrorCode(err)
		return
	}
	defer func() {
		log.Printf("Cleaning up the go server: %v", goServer)
		//testKillProcess(goServer.Process)
		//goServer.Process.Kill()
		// if goServer.ProcessState == nil || !goServer.ProcessState.Exited() {
		// 	log.Printf("Cleaning up the go server: %v", goServer.ProcessState)
		// 	goServer.Process.Kill()
		// }
	}()
	d, _ := time.ParseDuration("2s")
	time.Sleep(d)

	// Start PILA client
	goClient := exec.Command("go", "run", path.Join(*pilaClient, "main.go"))
	if debug {
		goClient.Stdout = os.Stdout
		goClient.Stderr = os.Stderr
	}
	err = goClient.Run()
	if err != nil {
		var found bool
		ret, found = testGetErrorCode(err)
		log.Printf("goClient.ret = %d; found = %v", ret, found)
		err = fmt.Errorf("Error executing the go client: %s\n", err.Error())
	}
	f = func() { testKillProcess(goServer.Process) }
	return ret, err, f
}

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
