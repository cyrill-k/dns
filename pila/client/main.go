package main

import (
	"flag"
	"log"
	"net"
	"os"
	"strconv"

	"github.com/cyrill-k/dns"
	"github.com/cyrill-k/dns/pila"
)

var records = map[string]string{
	"test.service.": "192.168.0.2",
}

var pilaConfig pila.PilaConfig

type ClientConfig struct {
	LocalPort  uint16
	LocalIP    net.IP
	RemotePort uint16
	RemoteIP   net.IP
}

func main() {
	// process CLI argument
	var config ClientConfig
	config.RemoteIP = net.ParseIP(*flag.String("remoteip", "127.0.0.1", "Server IP address"))
	config.LocalIP = net.ParseIP(*flag.String("localip", "127.0.0.1", "Client IP address"))
	config.RemotePort = uint16(*flag.Uint("remoteport", 7501, "Server IP address"))
	//config.RemoteIP = *flag.Uint("localport", "127.0.0.1", "Server IP address")
	flag.Parse()

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

	// verify signature
	var packedOriginalMessage []byte
	m.PackBuffer(packedOriginalMessage)
	err = pilaConfig.PilaVerify(in, packedOriginalMessage, config.LocalIP)
	if err != nil {
		log.Printf("[Client] PILA verification failed: %s", err.Error())
		os.Exit(pila.EXIT_CODE_VERIFICATION_FAILED)
	}

	log.Printf("[Client] Verified Response: %s\n", in.Answer[0].String())
}
