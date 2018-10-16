package main

import (
	"fmt"
	"log"
	"strconv"

	"github.com/cyrill-k/dns"
)

var records = map[string]string{
	"test.service.": "192.168.0.2",
}

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

	w.WriteMsg(m)
}

func main() {
	// // version 1) vendor/x
	// buf := make([]byte, 2, 514)
	// b := NewBuilder(buf, Header{})
	// // b.EnableCompression()
	// // Optionally start a section and add things to that section.
	// // Repeat adding sections as necessary.
	// b.StartQuestions()
	// buf, err := b.Finish()

	// version 2) 
	//c := new(dns.Client)
	//c.TsigSecret = map[string]string{"axfr.": "so6ZGir4GPAqINNh9U5c3A=="}
	m := new(dns.Msg)
	m.SetQuestion("test.service.", dns.TypeA)
	//m.SetTsig("axfr.", dns.HmacMD5, 300, time.Now().Unix())
	
	// start client
	port := 7501
	c := new(dns.Client)
	in, _, err := c.Exchange(m, "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		log.Fatalf("Failed to exchange message: %s\n ", err.Error())
	} else {
		log.Printf("Response: %s\n", in.String())
	}
}
