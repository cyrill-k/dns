package pila

import (
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/cyrill-k/dns"
)

const (
	pilaTxtNameString = "txt.pila."
	pilaSIGNameString = "sig.pila."
	pilaKEYNameString = "sig.pila."
)

// ***** PILA SIG

func createPilaSIG(algorithm uint8) *dns.SIG {
	now := uint32(time.Now().Unix())
	sigrr := new(dns.SIG)
	// values set in pilaSignRR()
	//sigrr.Header().Name = "."
	//sigrr.Header().Rrtype = TypeSIG
	//sigrr.Header().Class = ClassANY
	//sigrr.Header().Ttl = 0
	//sigrr.OrigTtl = 0
	//sigrr.TypeCovered = 0
	//sigrr.Labels = 0
	sigrr.Algorithm = algorithm
	sigrr.Expiration = now + 300
	sigrr.Inception = now - 300
	sigrr.KeyTag = generateKeyTag()
	sigrr.SignerName = pilaSIGNameString
	//sigrr.Signature = "" default value
	domainNameLength, _ := dns.PackDomainName(sigrr.SignerName, nil, 0, nil, false)
	signatureWireFormat, _ := u.FromBase64([]byte(sigrr.Signature))
	signatureWireLength := len(signatureWireFormat)
	sigrr.Header().Rdlength = 2 + 1 + 1 + 4 + 4 + 4 + 2 + uint16(domainNameLength) + uint16(signatureWireLength)
	return sigrr
}

func getPilaSIG(m *dns.Msg) (*dns.SIG, error) {
	rr := getLastExtraRecord(m, dns.TypeSIG)
	if rr == nil {
		return nil, errors.New("No Extra TypeSIG record available")
	}
	sig, ok := rr.(*dns.SIG)
	if !ok {
		return nil, errors.New("Last Extra record with type TypeSIG cannot be transformed into a SIG record")
	}
	if sig.SignerName != pilaSIGNameString {
		return nil, errors.New("Last Extra SIG record is not a PILA SIG record")
	}
	return rr.(*dns.SIG), nil
}

func getAdditionalInfo(rr *dns.SIG, request []byte, srcIdentifier []byte) ([]byte, error) {
	hash, ok := dns.AlgorithmToHash[rr.Algorithm]
	if !ok {
		return nil, dns.ErrAlg
	}

	hasher := hash.New()
	// Include the request if possible
	hasher.Write(request)

	// Include the endpoint identifier to inhibit source address spoofing
	hasher.Write(srcIdentifier)

	return hasher.Sum(nil), nil
}

func generateKeyTag() uint16 {
	return 42
}

func logSIG(data []byte, lengthHeaderName int, lengthSignerName int, totalLength int) string {
	var off int
	builder := new(strings.Builder)
	off = logSliceStringDomainName("Header.Name", off, 15, data, builder)
	off = logSliceString16("Header.Rrtype", off, data, builder)
	off = logSliceString16("Header.Class", off, data, builder)
	off = logSliceString32("Header.Ttl", off, data, builder)
	off = logSliceString16("Header.Rdlength", off, data, builder)
	off = logSliceString16("TypeCovered", off, data, builder)
	off = logSliceString8("Algorithm", off, data, builder)
	off = logSliceString8("Labels", off, data, builder)
	off = logSliceString32("OrigTtl", off, data, builder)
	off = logSliceString32("Expiration", off, data, builder)
	off = logSliceString32("Inception", off, data, builder)
	off = logSliceString16("KeyTag", off, data, builder)
	off = logSliceStringDomainName("SignerName", off, 15, data, builder)
	off = logSliceStringHex("Signature", off, totalLength-off, data, builder)
	return builder.String()
}

// ***** PILA KEY

func createPilaKEY(protocol uint8, algorithm uint8, publicKeyBase64 string) *dns.KEY {
	log.Println("createPilaKey")
	key := new(dns.KEY)
	key.Header().Name = pilaKEYNameString
	key.Header().Rrtype = dns.TypeKEY
	key.Header().Class = dns.ClassANY
	key.Flags = 0
	key.Protocol = protocol
	key.Algorithm = algorithm
	key.PublicKey = publicKeyBase64
	return key
}

// ***** PILA TXT

type PilaTxtStruct struct {
	// Adds randomness to a request in order to prevent replay attacks
	Randomness []byte
	// A list of certificates used to authenticate this message from the root of
	// trust (TRC in case of SCION) to the certificate authenticating the IP
	// address of the server
	CertificateChainRaw []byte
}

func createPilaTxtRecord(randomnessLength int, certificatesRaw []byte) ([]byte, error) {
	randValue, err := GenerateRandomness(randomnessLength)
	if err != nil {
		return nil, errors.New("Error generating randomness for PILA TXT record: " + err.Error())
	}
	txtStruct := PilaTxtStruct{Randomness: randValue, CertificateChainRaw: certificatesRaw}
	txtEncoded, error := asn1.Marshal(txtStruct)
	if error != nil {
		return nil, errors.New("Cannot marshal PilaTxtStruct")
	}
	return txtEncoded, nil
}

func combineTxtResources(txtStrings []string) string {
	var bLog strings.Builder
	var b strings.Builder
	for i, s := range txtStrings {
		b.Write([]byte(s))
		if i != 0 {
			bLog.Write([]byte(", "))
		}
		bLog.Write([]byte(fmt.Sprintf("(%d)", len(s))))
	}
	bLog.Write([]byte(fmt.Sprintf(" tot = %d", len(b.String()))))
	log.Println(bLog.String())
	return b.String()
}

func minInt(x, y int) int {
	if x < y {
		return x
	}
	return y
}

// splits content into an array of strings of size <= 255.
// Stops splitting as soon as the maximum allowed content
// size is reached (2^16-2^8) and returns an offset of the
// next byte in content that was not yet added to the array.
func splitTxtResources(content string) (txtStrings []string, off int) {
	// max allowed size for txt resource record RDATA is 2^16
	// Since one byte per txtstring is used to indicate the size
	// of the txtstring, the maximum allowed content size is
	// 2^8*(2^8-1) = 2^16 - 2^8
	for off < len(content) {
		newOff := minInt(off+255, len(content))
		txtStrings = append(txtStrings, content[off:newOff])
		off = newOff
		if off >= (1<<16)-(1<<8) {
			break
		}
	}
	return
}

func addPilaTxtRecord(m *dns.Msg, requestingSignature bool, providingSignature bool, certificateChainRaw []byte) error {
	var randomnessLength int
	if requestingSignature {
		randomnessLength = 8
	}
	txtContent, error := createPilaTxtRecord(randomnessLength, certificateChainRaw)
	if error != nil {
		return error
	}
	var rr dns.RR
	//todo(cyrill): split content into different txt string records
	txtStringRecords, off := splitTxtResources(string(txtContent))
	if len(txtContent) != off {
		return fmt.Errorf("Couldn't fit certificate chain into txt record. Added %d of %d bytes", off, len(txtContent))
	}
	rr = &dns.TXT{Hdr: dns.RR_Header{Name: pilaTxtNameString, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0}, Txt: txtStringRecords}
	m.Extra = append(m.Extra, rr)
	return nil
}

// Decodes an escaped string: \" & \DDD into the corresponding byte string.
// Returns an error if the size of the decoded string is larger than 255 bytes.
func decodeTxtRecordString(in string) (string, error) {
	buf := make([]byte, 256)
	_, err := u.PackString(in, buf[:], 0)
	if err != nil {
		return "", errors.New("Error decoding TXT string entries: " + err.Error())
	}
	return string(buf[1:]), nil
}

func getPilaTxtRecord(m *dns.Msg, doNotDecodeTxtStrings ...bool) (*PilaTxtStruct, error) {
	// No additional records
	if len(m.Extra) == 0 {
		return nil, errors.New("No additional resource records present")
	}

	rr := getLastExtraRecord(m, dns.TypeTXT).(*dns.TXT)
	if rr == nil {
		return nil, errors.New("No txt records present")
	}
	log.Printf("last extra record: %s", rr.String())

	var shouldNotDecodeTxtStrings bool
	if len(doNotDecodeTxtStrings) == 1 {
		shouldNotDecodeTxtStrings = doNotDecodeTxtStrings[0]
	}

	// not pila txt record
	if rr.Header().Name != pilaTxtNameString {
		return nil, errors.New("Last txt record is not: " + pilaTxtNameString + " txt record")
	}

	if len(rr.Txt) == 0 {
		return nil, errors.New("Empty txt record")
	}
	log.Printf("len(rr.Txt) = %d", len(rr.Txt))

	var decodedStrings []string
	if !shouldNotDecodeTxtStrings {
		decodedStrings = make([]string, len(rr.Txt))
		for i, s := range rr.Txt {
			var err error
			decodedStrings[i], err = decodeTxtRecordString(s)
			if err != nil {
				return nil, errors.New("Error decoding TXT string entries: " + err.Error())
			}
		}
	} else {
		decodedStrings = rr.Txt
	}
	log.Println("Decoded strings:")
	for i, s := range decodedStrings {
		log.Printf("[%d] %s\n", i, s)
	}
	txtStringsCombined := combineTxtResources(decodedStrings)
	var s PilaTxtStruct
	if _, err := asn1.Unmarshal([]byte(txtStringsCombined), &s); err != nil {
		return nil, errors.New("ASN1 Unmarshal failed: " + err.Error())
	}
	return &s, nil
}

// ***** OPT record for large DNS messages

func addPilaOptRecord(m *dns.Msg, maxUdpSize uint16, do bool) {
	// create opt record (EDNS0)
	m.SetEdns0(maxUdpSize, do)

	// opt := new(OPT)
	// opt.Header().Name = "."
	// opt.Header().Rrtype = TypeOPT
	// //opt.Header().Class = 4096
	// //opt.Header().Ttl = 0
	// //opt.Header().Rdlength = 0
	// opt.SetUDPSize(maxUdpSize)

	// // add record to m
	// m.Extra = append(m.Extra, opt)
}

// ***** Helper functions

func getLastExtraRecord(m *dns.Msg, typeCovered uint16) dns.RR {
	for i := len(m.Extra) - 1; i >= 0; i-- {
		if m.Extra[i].Header().Rrtype == typeCovered {
			return m.Extra[i]
		}
	}
	return nil
}

func logSliceStringHex(identifier string, from int, length int, buffer []byte, b *strings.Builder) int {
	hexString := hex.EncodeToString(buffer[from : from+length])
	b.Write([]byte(", " + identifier + "(" + strconv.Itoa(from) + ":" + strconv.Itoa(from+length) + ") = " + hexString))
	return from + length
}

func logSliceStringDomainName(identifier string, from int, length int, buffer []byte, b *strings.Builder) int {
	b.Write([]byte(", " + identifier + "(" + strconv.Itoa(from) + ":" + strconv.Itoa(from+length) + ") = "))

	var counter uint8
	var i int
	for ; i < length || length == 0; i++ {
		if counter == 0 {
			counter = uint8(buffer[from+i])
			b.Write([]byte("[" + strconv.FormatUint(uint64(counter), 10) + "]"))
			if counter == 0 {
				break
			}
		} else {
			b.Write(buffer[from+i : from+i+1])
			counter--
		}
	}
	return from + i + 1
}

func logSliceStringString(identifier string, from int, length int, buffer []byte, b *strings.Builder) int {
	rawString := string(buffer[from : from+length])
	b.Write([]byte(", " + identifier + "(" + strconv.Itoa(from) + ":" + strconv.Itoa(from+length) + ") = " + rawString))
	return from + length
}

func logSliceString8(identifier string, from int, buffer []byte, b *strings.Builder) int {
	b.Write([]byte(", " + identifier + "(" + strconv.Itoa(from) + ":" + strconv.Itoa(from+1) + ") = " + strconv.FormatUint(uint64(buffer[from]), 10)))
	return from + 1
}

func logSliceString16(identifier string, from int, buffer []byte, b *strings.Builder) int {
	b.Write([]byte(", " + identifier + "(" + strconv.Itoa(from) + ":" + strconv.Itoa(from+2) + ") = " + strconv.FormatUint(uint64(binary.BigEndian.Uint16(buffer[from:from+2])), 10)))
	return from + 2
}

func logSliceString32(identifier string, from int, buffer []byte, b *strings.Builder) int {
	b.Write([]byte(", " + identifier + "(" + strconv.Itoa(from) + ":" + strconv.Itoa(from+4) + ") = " + strconv.FormatUint(uint64(binary.BigEndian.Uint32(buffer[from:from+4])), 10)))
	return from + 4
}
