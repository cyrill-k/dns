package dns

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"strings"
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
	pilaServer   = flag.String("server", "/home/cyrill/go/src/github.com/cyrill-k/dns/pila/server", "PILA GO client folder")
	pilaClient   = flag.String("client", "/home/cyrill/go/src/github.com/cyrill-k/dns/pila/client", "PILA GO server folder")
)

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
			t.Fatalf("Other error than fake signature detected")
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
		log.Printf("scion script failed: %s", err.Error())
		ret, _ = testGetErrorCode(err)
		return
	}

	// Build PILA server
	goServerPath := path.Join(*pilaServer, "main.go")
	goServerExePath := path.Join(*pilaServer, "main")
	err = testBuildGoSource(goServerExePath, goServerPath)
	if err != nil {
		return
	}

	// Build PILA client
	goClientPath := path.Join(*pilaClient, "main.go")
	goClientExePath := path.Join(*pilaClient, "main")
	err = testBuildGoSource(goClientExePath, goClientPath)
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
		goServer.Stdout = os.Stdout
		goServer.Stderr = os.Stderr
	}
	// allow killing process spawned by goServer process
	testAllowProcessKill(goServer)
	err = goServer.Start()
	if err != nil {
		ret, _ = testGetErrorCode(err)
		return
	}

	defer func() {
		log.Printf("Cleaning up the go server...")
		testKillProcess(goServer.Process)
	}()
	//todo(cyrill): optimize by reading server output and
	// continuing as soon as "Starting at XXXX" is read
	d, _ := time.ParseDuration("2s")
	time.Sleep(d)

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
