package pila

import (
	"bytes"
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"github.com/cyrill-k/dns"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/crypto/cert"
	"github.com/scionproto/scion/go/lib/crypto/trc"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
)

const (
	EXIT_CODE_EXCHANGE_FAILED     = 2
	EXIT_CODE_VERIFICATION_FAILED = 3
	EXIT_CODE_INTERNAL_ERROR      = 4
)

var u dns.PilaUtility = dns.PilaUtility{}

type PostSignFunction func([]byte) []byte

type PilaConfig struct {
	lAddr, csAddr                       *snet.Addr
	lIA                                 addr.IA
	sciondPath, dispatcherPath, trcPath string
	port                                uint16
	certificateServerReadDeadline       time.Duration
	MaxUdpSize                          uint16
	environmentInitialized              bool
}

func PostSignNoOp(in []byte) []byte {
	return in
}

func (c *PilaConfig) InitializeEnvironment() {
	if c.environmentInitialized {
		os.Setenv("TZ", "UTC")
	}
}

func DefaultConfig() PilaConfig {
	csReadDeadline, err := time.ParseDuration("500ms")
	if err != nil {
		panic(err)
	}
	lAddr, err := snet.AddrFromString("17-1039,[127.0.0.1]:0")
	if err != nil {
		panic(err)
	}
	csAddr, err := snet.AddrFromString("17-1039,[127.0.0.1]:31043")
	if err != nil {
		panic(err)
	}
	lIA, err := addr.IAFromString("17-1039")
	if err != nil {
		panic(err)
	}

	return PilaConfig{
		lAddr:          lAddr,
		csAddr:         csAddr,
		lIA:            lIA,
		sciondPath:     sciond.GetDefaultSCIONDPath(nil),
		dispatcherPath: "/run/shm/dispatcher/default.sock",
		trcPath:        "/home/cyrill/go/src/github.com/scionproto/scion/gen/ISD17/AS1039/cs17-1039-1/certs/ISD17-V1.trc",
		port:           50123,
		certificateServerReadDeadline: csReadDeadline,
		MaxUdpSize:                    4096}
}

// Returns a default private, public key pair, a corresponsing PILA certificate chain, and a matching request response pair
func ReadConfigFromFolder(root string) (priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey, chain *cert.PilaChain, request *dns.Msg, response *dns.Msg) {
	priv, pub, chain = ReadKeysAndCertChainFromFolder(root)
	chain, _ = ReadPilaCertificateChain(path.Join(root, "pilachain"))

	requestRaw, err := ioutil.ReadFile(path.Join(root, "request"))
	if err == nil {
		request = new(dns.Msg)
		err = request.Unpack(requestRaw)
		// if err != nil {
		// 	log.Fatalf("Error unpacking stored message: %s\n", err.Error())
		// }
	}

	responseRaw, err := ioutil.ReadFile(path.Join(root, "response"))
	if err == nil {
		response = new(dns.Msg)
		err = response.Unpack(responseRaw)
		// if err != nil {
		// 	log.Fatalf("Error unpacking stored message: %s\n", err.Error())
		// }
	}
	return
}

func ReadP256Config() (priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey, chain *cert.PilaChain, request *dns.Msg, response *dns.Msg) {
	return ReadConfigFromFolder("P256")
}

func ReadP384Config() (priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey, chain *cert.PilaChain, request *dns.Msg, response *dns.Msg) {
	return ReadConfigFromFolder("P384")
}

func (c *PilaConfig) readTrc() (*trc.TRC, error) {
	//todo(cyrill): compression should maybe be true?
	trc, err := trc.TRCFromFile(c.trcPath, false)
	if err != nil {
		return nil, err
	}
	return trc, nil
}

func GenerateRandomness(size int) ([]byte, error) {
	//todo(cyrill): Entropy of the seed?
	result := make([]byte, size)
	_, err := rand.Read(result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func DebugPrint(msgName string, m *dns.Msg) {
	log.Println("\n***** " + msgName + ": \n" + m.String() + "\n*****\n\n")
}

// https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
func encode(ip net.IP) []byte {
	var encoded []byte
	if len(ip) == net.IPv4len || (len(ip) == net.IPv6len && bytes.Equal(ip, ip.To4())) {
		encoded = append(encoded, uint8(pilaIPv4))
		encoded = append(encoded, ip.To16()...)
	} else if len(ip) == net.IPv6len {
		encoded = append(encoded, uint8(pilaIPv6))
		encoded = append(encoded, ip.To16()...)
	}
	return encoded
}

func (c *PilaConfig) PilaRequestSignature(m *dns.Msg) error {
	addPilaTxtRecord(m, false, true, []byte{})
	//todo(cyrill): set/unset DO bit in client
	addPilaOptRecord(m, c.MaxUdpSize, false)
	return nil
}

func (conf *PilaConfig) PilaSign(m *dns.Msg, packedOriginalMessage []byte, signalg SignerWithAlgorithm, peerIP net.IP, postSign PostSignFunction, chain *cert.PilaChain) error {
	// Extract public key
	pub, err := GetPublicKeyWithAlgorithm(signalg)
	if err != nil {
		return errors.New("Failed to extract public key to send to the certificate server: " + err.Error())
	}

	if chain == nil {
		// Request certificate of public key
		h := NewASCertificateHandler(conf)
		chain, err = h.PilaRequestASCertificate(pub)
		if err != nil {
			return err
		}
		jsonRepresentation, err := chain.JSON(false)
		if err != nil {
			log.Fatalf("Failed to create JSON encoding of PilaChain: " + err.Error())
		}
		log.Print(string(jsonRepresentation))
	}

	// Add JSON encoded certificate chain to reply using a TXT record
	jsonEncodedPilaChain, err := chain.JSON(false)
	if err != nil {
		return errors.New("Failed to create JSON encoding of PilaChain: " + err.Error())
	}
	addPilaTxtRecord(m, false, true, []byte(jsonEncodedPilaChain))

	// Create SIG record to store signature over the message
	sigrr := createPilaSIG(signalg.Algorithm())

	// Create verification context using the corresponding reply & peer identifier
	additionalInfo, err := getAdditionalInfo(sigrr, packedOriginalMessage, encode(peerIP))
	if err != nil {
		return errors.New("Failed to extract additional info from request")
	}

	// Sign message + verification context & add SIG resource record
	signedMsgPacked, err := pilaSignRR(sigrr, signalg.Signer(), m, additionalInfo, postSign)
	if err != nil {
		return errors.New("Failed PILA signature: " + err.Error())
	}

	// Set SIG resource record in response
	if err := m.Unpack(signedMsgPacked); err != nil {
		return errors.New("Failed to unpack signed msg: " + err.Error())
	}

	return nil
}

func (conf *PilaConfig) PilaVerify(m *dns.Msg, packedOriginalMessage []byte, localIp net.IP) error {
	// Retrieve (PILA) SIG record from message
	sigrr, err := getPilaSIG(m)
	if err != nil {
		return errors.New("Error reading last SIG record from dns message: " + err.Error())
	}
	if sigrr == nil {
		return errors.New("No PILA SIG record available")
	}

	// extract TXT record containing the certificate chain
	pilaTxt, err := getPilaTxtRecord(m)
	if err != nil {
		return errors.New("Failed to decode PILA TXT record: " + err.Error())
	}

	// extract the certificate chain
	pilaChain, err := cert.PilaChainFromRaw(pilaTxt.CertificateChainRaw)
	if err != nil {
		return errors.New("Failed to parse PILA certificate chain: " + err.Error())
	}

	// verify certificate chain using locally stored trc
	trc, err := conf.readTrc()
	if err := pilaChain.Verify(cert.PilaCertificateEntity{Ipv4: localIp}, trc); err != nil {
		return errors.New("Failed to verify PILA certificate chain: " + err.Error())
	}

	// get public key from leaf cert and set corresponding algorithm & base64 pubkey
	var algorithm uint8
	switch pilaChain.Endpoint.SignAlgorithm {
	case "ECDSAP256SHA256":
		algorithm = dns.ECDSAP256SHA256
	case "ECDSAP384SHA384":
		algorithm = dns.ECDSAP384SHA384
	default:
		return errors.New("Unsupported signing algorithm in endpoint certificate: " + pilaChain.Endpoint.SignAlgorithm)
	}
	pubKeyBase64 := u.ToBase64(pilaChain.Endpoint.SubjectSignKey)

	// Create verification context based on original message & local endpoint identifier
	additionalInfo, err := getAdditionalInfo(sigrr, packedOriginalMessage, encode(localIp))
	if err != nil {
		return errors.New("Failed to extract additional info from request")
	}

	// Create dns.KEY object to verify signature
	key := createPilaKEY(3, algorithm, pubKeyBase64)

	// Verify signature
	buf, err := m.Pack()
	if err != nil {
		return errors.New("Failed to pack message: " + err.Error())
	}
	error := pilaVerifyRR(sigrr, key, buf, additionalInfo)
	return error
}

// Sign signs a Msg. It fills the signature with the appropriate data.
// The SIG record should have the SignerName, KeyTag, Algorithm, Inception
// and Expiration set.
func pilaSignRR(rr *dns.SIG, k crypto.Signer, m *dns.Msg, additionalInfo []byte, postSign PostSignFunction) ([]byte, error) {
	if k == nil {
		return nil, dns.ErrPrivKey
	}
	if rr.KeyTag == 0 || len(rr.SignerName) == 0 || rr.Algorithm == 0 {
		return nil, dns.ErrKey
	}
	rr.Header().Rrtype = dns.TypeSIG
	rr.Header().Class = dns.ClassANY
	rr.Header().Ttl = 0
	rr.Header().Name = "."
	rr.OrigTtl = 0
	rr.TypeCovered = 0
	rr.Labels = 0

	buf := make([]byte, m.Len()+u.Len(rr))
	mbuf, err := m.PackBuffer(buf)
	if err != nil {
		return nil, err
	}
	if &buf[0] != &mbuf[0] {
		return nil, dns.ErrBuf
	}
	off, err := dns.PackRR(rr, buf, len(mbuf), nil, false)
	if err != nil {
		return nil, err
	}
	buf = buf[:off:cap(buf)]

	hash, ok := dns.AlgorithmToHash[rr.Algorithm]
	if !ok {
		return nil, dns.ErrAlg
	}

	hasher := hash.New()
	// Write SIG rdata
	hasher.Write(buf[len(mbuf)+1+2+2+4+2:])
	// Write message
	hasher.Write(buf[:len(mbuf)])
	// Write additional info
	hasher.Write(additionalInfo)

	signature, err := u.Sign(k, hasher.Sum(nil), hash, rr.Algorithm)
	if err != nil {
		return nil, err
	}

	signature = postSign(signature)

	rr.Signature = u.ToBase64(signature)

	buf = append(buf, signature...)
	if len(buf) > int(^uint16(0)) {
		return nil, dns.ErrBuf
	}
	// Adjust sig data length
	rdoff := len(mbuf) + 1 + 2 + 2 + 4
	rdlen := binary.BigEndian.Uint16(buf[rdoff:])
	rdlen += uint16(len(signature))
	binary.BigEndian.PutUint16(buf[rdoff:], rdlen)
	// Adjust additional count
	adc := binary.BigEndian.Uint16(buf[10:])
	adc++
	binary.BigEndian.PutUint16(buf[10:], adc)

	return buf, nil
}

// Verify validates the message buf using the key k.
// It's assumed that buf is a valid message from which rr was unpacked.
func pilaVerifyRR(rr *dns.SIG, k *dns.KEY, buf []byte, additionalInfo []byte) error {
	if k == nil {
		return dns.ErrKey
	}
	if rr.KeyTag == 0 || len(rr.SignerName) == 0 || rr.Algorithm == 0 {
		return dns.ErrKey
	}

	var hash crypto.Hash
	switch rr.Algorithm {
	case dns.DSA, dns.RSASHA1:
		hash = crypto.SHA1
	case dns.RSASHA256, dns.ECDSAP256SHA256:
		hash = crypto.SHA256
	case dns.ECDSAP384SHA384:
		hash = crypto.SHA384
	case dns.RSASHA512:
		hash = crypto.SHA512
	default:
		return dns.ErrAlg
	}
	hasher := hash.New()

	buflen := len(buf)
	qdc := binary.BigEndian.Uint16(buf[4:])
	anc := binary.BigEndian.Uint16(buf[6:])
	auc := binary.BigEndian.Uint16(buf[8:])
	adc := binary.BigEndian.Uint16(buf[10:])
	offset := 12
	var err error
	for i := uint16(0); i < qdc && offset < buflen; i++ {
		_, offset, err = dns.UnpackDomainName(buf, offset)
		if err != nil {
			return err
		}
		// Skip past Type and Class
		offset += 2 + 2
	}
	for i := uint16(1); i < anc+auc+adc && offset < buflen; i++ {
		_, offset, err = dns.UnpackDomainName(buf, offset)
		if err != nil {
			return err
		}
		// Skip past Type, Class and TTL
		offset += 2 + 2 + 4
		if offset+1 >= buflen {
			continue
		}
		rdlen := binary.BigEndian.Uint16(buf[offset:])
		offset += 2
		offset += int(rdlen)
	}
	if offset >= buflen {
		return errors.New("dns: overflowing unpacking signed message")
	}

	// offset should be just prior to SIG
	bodyend := offset
	// owner name SHOULD be root
	_, offset, err = dns.UnpackDomainName(buf, offset)
	if err != nil {
		return err
	}
	// Skip Type, Class, TTL, RDLen
	offset += 2 + 2 + 4 + 2
	sigstart := offset
	// Skip Type Covered, Algorithm, Labels, Original TTL
	offset += 2 + 1 + 1 + 4
	if offset+4+4 >= buflen {
		return errors.New("dns: overflow unpacking signed message")
	}
	expire := binary.BigEndian.Uint32(buf[offset:])
	offset += 4
	incept := binary.BigEndian.Uint32(buf[offset:])
	offset += 4
	now := uint32(time.Now().Unix())
	if now < incept || now > expire {
		return dns.ErrTime
	}
	// Skip key tag
	offset += 2
	var signername string
	signername, offset, err = dns.UnpackDomainName(buf, offset)
	if err != nil {
		return err
	}
	// If key has come from the DNS name compression might
	// have mangled the case of the name
	if strings.ToLower(signername) != strings.ToLower(k.Header().Name) {
		return errors.New("dns: signer name doesn't match key name")
	}
	sigend := offset
	hasher.Write(buf[sigstart:sigend])
	hasher.Write(buf[:10])
	hasher.Write([]byte{
		byte((adc - 1) << 8),
		byte(adc - 1),
	})
	hasher.Write(buf[12:bodyend])
	// Write additional info
	hasher.Write(additionalInfo)

	hashed := hasher.Sum(nil)
	sig := buf[sigend:]
	switch k.Algorithm {
	case dns.DSA:
		pk := u.PublicKeyDSA(k)
		sig = sig[1:]
		r := big.NewInt(0)
		r.SetBytes(sig[:len(sig)/2])
		s := big.NewInt(0)
		s.SetBytes(sig[len(sig)/2:])
		if pk != nil {
			if dsa.Verify(pk, hashed, r, s) {
				return nil
			}
			return dns.ErrSig
		}
	case dns.RSASHA1, dns.RSASHA256, dns.RSASHA512:
		pk := u.PublicKeyRSA(k)
		if pk != nil {
			return rsa.VerifyPKCS1v15(pk, hash, hashed, sig)
		}
	case dns.ECDSAP256SHA256, dns.ECDSAP384SHA384:
		pk := u.PublicKeyECDSA(k)
		r := big.NewInt(0)
		r.SetBytes(sig[:len(sig)/2])
		s := big.NewInt(0)
		s.SetBytes(sig[len(sig)/2:])
		if pk != nil {
			if ecdsa.Verify(pk, hashed, r, s) {
				return nil
			}
			return dns.ErrSig
		}
	}
	return dns.ErrKeyAlg
}
