package main

import (
	"flag"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"
	"strconv"

	"github.com/cyrill-k/dns"
	"github.com/cyrill-k/dns/pila"
)

var (
	records = map[string]string{
		"test.service.": "192.168.0.2",
	}

	pilaConfig pila.PilaConfig

	disableLoggingFlag = flag.Bool("disable-logging", false, "Disable message logging")
	remoteIPFlag       = flag.String("remote-ip", "127.0.0.1", "Server IP address")
	localIPFlag        = flag.String("local-ip", "127.0.0.1", "Client IP address")
	remotePortFlag     = flag.Uint("remote-port", 7501, "Server IP address")
	storeMsgFolderFlag = flag.String("store-msg-folder", "-", "Folder to store the request and returned response (\"request\", \"response\"")
)

type ClientConfig struct {
	LocalPort  uint16
	LocalIP    net.IP
	RemotePort uint16
	RemoteIP   net.IP
}

func main() {
	flag.Parse()

	// process CLI argument
	var config ClientConfig
	config.RemoteIP = net.ParseIP(*remoteIPFlag)
	config.LocalIP = net.ParseIP(*localIPFlag)
	config.RemotePort = uint16(*remotePortFlag)
	//config.RemoteIP = *flag.Uint("localport", "127.0.0.1", "Server IP address")

	if *disableLoggingFlag {
		log.SetFlags(0)
		log.SetOutput(ioutil.Discard)
	}

	pilaConfig = pila.DefaultConfig()
	pilaConfig.InitializeEnvironment()

	m := new(dns.Msg)
	m.SetQuestion("test.service.", dns.TypeA)
	pilaConfig.PilaRequestSignature(m)

	// start client
	c := new(dns.Client)
	c.UDPSize = pilaConfig.MaxUdpSize

	// perform exchange
	log.Printf("[Client] Sending request (id=%d)\n", m.Id)
	in, _, err := c.Exchange(m, config.RemoteIP.String()+":"+strconv.FormatUint(uint64(config.RemotePort), 10))
	if err != nil {
		log.Printf("[Client] Failed to exchange message: %s\n ", err.Error())
		os.Exit(pila.EXIT_CODE_EXCHANGE_FAILED)
	}

	// store conversation
	if *storeMsgFolderFlag != "-" {
		rawRequest, err := m.Pack()
		if err != nil {
			log.Printf("[Client] Failed to pack request to store in file: %s\n", err.Error())
		}
		ioutil.WriteFile(path.Join(*storeMsgFolderFlag, "request"), rawRequest, 0644)

		rawResponse, err := in.Pack()
		if err != nil {
			log.Printf("[Client] Failed to pack response to store in file: %s\n", err.Error())
		}
		ioutil.WriteFile(path.Join(*storeMsgFolderFlag, "response"), rawResponse, 0644)
	}

	// verify signature
	packedOriginalMessage, err := m.Pack()
	if err != nil {
		log.Printf("[Client] Failed to pack request into buffer: %s\n ", err.Error())
		os.Exit(pila.EXIT_CODE_INTERNAL_ERROR)
	}
	log.Printf("packed orig msg: %+v\n", packedOriginalMessage)
	err = pilaConfig.PilaVerify(in, packedOriginalMessage, config.LocalIP)
	if err != nil {
		log.Printf("[Client] PILA verification failed: %s", err.Error())
		os.Exit(pila.EXIT_CODE_VERIFICATION_FAILED)
	}

	log.Printf("[Client] Verified Response: %s\n", in.Answer[0].String())
}
