package dns

import (
	"bytes"
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"strconv"
	"strings"
	"time"

	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/crypto/cert"
	"github.com/scionproto/scion/go/lib/crypto/trc"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
)

type EndpointIdentifierType int

const (
	pilaTxtNameString                                  = "txt.pila."
	pilaSIGNameString                                  = "sig.pila."
	pilaKEYNameString                                  = "sig.pila."
	pilaASCertificateSignedName                        = "PILA CERTIFICATE"
	pilaIPv4                    EndpointIdentifierType = 1
	pilaIPv6                    EndpointIdentifierType = 2
	pilaScion                   EndpointIdentifierType = 100 // temporary assignment
	MaxTries                                           = 3
	MaxResponseSizeInBytes                             = 10000
)

type SignerWithAlgorithm interface {
	Signer() crypto.Signer
	Algorithm() uint8
}

type PublicKeyWithAlgorithm interface {
	PublicKeyBase64() string
	Algorithm() uint8
}

type PilaConfig struct {
	lAddr, csAddr                       *snet.Addr
	lIA                                 addr.IA
	sciondPath, dispatcherPath, trcPath string
	port                                uint16
	certificateServerReadDeadline       time.Duration
	MaxUdpSize                          uint16
}

func (c *PilaConfig) ReadTrc() (*trc.TRC, error) {
	//todo(cyrill): compression should maybe be true?
	trc, err := trc.TRCFromFile(c.trcPath, false)
	if err != nil {
		return nil, err
	}
	return trc, nil
}

type EndpointIdentifier interface {
	MarshalText() ([]byte, error)
}

func DefaultConfig() PilaConfig {
	csReadDeadline, err := time.ParseDuration("500ms")
	if err != nil {
		panic(err)
	}
	lAddr, err := snet.AddrFromString("17-1039,[127.0.0.1]:80")
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

func GetPublicKeyWithAlgorithm(signalg SignerWithAlgorithm) (PublicKeyWithAlgorithm, error) {
	log.Printf("get pub key: %T\n", signalg)
	switch signalg.Signer().(type) {
	case *ecdsa.PrivateKey:
		return NewECDSAPublicKey(signalg.Signer().Public().(*ecdsa.PublicKey)), nil
	}
	return nil, errors.New("Unsupported private key cannot be converted into public key")
}

func GetPublicKeyRaw(pubKey PublicKeyWithAlgorithm) ([]byte, error) {
	return fromBase64([]byte(pubKey.PublicKeyBase64()))
}

type ECDSASigner struct {
	PrivateKey     *ecdsa.PrivateKey
	AlgorithmValue uint8
}

type ECDSAPublicKey struct {
	PublicKey      *ecdsa.PublicKey
	AlgorithmValue uint8
}

func (signer *ECDSASigner) Signer() crypto.Signer {
	return signer.PrivateKey
}

func (signer *ECDSASigner) Algorithm() uint8 {
	return signer.AlgorithmValue
}

func (pub *ECDSAPublicKey) PublicKeyBase64() string {
	var lenbuf int
	switch pub.PublicKey.Curve {
	case elliptic.P256():
		lenbuf = 64
	case elliptic.P384():
		lenbuf = 96
	}
	buffer := make([]byte, lenbuf)
	// log.Println("last byte = " + strconv.Itoa(int(buffer[lenbuf-1])) + "lenbuf/2=" + strconv.Itoa(lenbuf/2))
	// log.Println("pub length = " + strconv.Itoa(lenbuf) + ", pub X.Bytes() length = " + strconv.Itoa(len(pub.PublicKey.X.Bytes())) + ", pub Y.Bytes() length = " + strconv.Itoa(len(pub.PublicKey.Y.Bytes())))
	// log.Println("buf len = " + strconv.Itoa(len(buffer[:lenbuf/2])) + ", pubkey len = " + strconv.Itoa(len(pub.PublicKey.X.Bytes())))
	// log.Println("buf len = " + strconv.Itoa(len(buffer[lenbuf/2:])) + ", pubkey len = " + strconv.Itoa(len(pub.PublicKey.Y.Bytes())))
	copy(buffer[:lenbuf/2], pub.PublicKey.X.Bytes())
	copy(buffer[lenbuf/2:], pub.PublicKey.Y.Bytes())
	// log.Println("test before return: " + strconv.Itoa(len(buffer)))
	// x := base64.StdEncoding.EncodeToString(buffer)
	// log.Println("test2: " + x)
	// return x
	return toBase64(buffer)
}

func (pub *ECDSAPublicKey) Algorithm() uint8 {
	return pub.AlgorithmValue
}

func NewECDSASigner(privateKey *ecdsa.PrivateKey) SignerWithAlgorithm {
	var algorithm uint8
	switch privateKey.Curve {
	case elliptic.P256():
		algorithm = ECDSAP256SHA256
	case elliptic.P384():
		algorithm = ECDSAP384SHA384
	}
	signer := ECDSASigner{
		PrivateKey:     privateKey,
		AlgorithmValue: algorithm,
	}
	return &signer
}

func NewECDSAPublicKey(publicKey *ecdsa.PublicKey) PublicKeyWithAlgorithm {
	var algorithm uint8
	switch publicKey.Curve {
	case elliptic.P256():
		algorithm = ECDSAP256SHA256
	case elliptic.P384():
		algorithm = ECDSAP384SHA384
	}
	signer := ECDSAPublicKey{
		PublicKey:      publicKey,
		AlgorithmValue: algorithm,
	}
	return &signer
}

type PilaGeneralCertificate interface {
	Pack() ([]byte, error)
}

type PilaVerifyingCertificate interface {
	PilaGeneralCertificate
	Verify(content []byte) error
	VerifyCertificate(certificate PilaGeneralCertificate) error
}

type PilaSigningCertificate interface {
	PilaGeneralCertificate
	Sign(content []byte) ([]byte, error)
}

// Not used? server -> signing, client -> verifying
type PilaFullCertificate interface {
	PilaGeneralCertificate
	Verify(content []byte) error
	VerifyCertificate(certificate PilaGeneralCertificate) error
	Sign(content []byte) ([]byte, error)
}

type ScionTrc struct {
	trc cert_mgmt.TRC
}

func (*ScionTrc) VerifySignature(content []byte) error {
	//todo(cyrill):

	return errors.New("TODO")
}

func (trc *ScionTrc) VerifyCertificate(certificate PilaGeneralCertificate) error {
	rawCert, err := certificate.Pack()
	if err != nil {
		return err
	}
	return trc.VerifySignature(rawCert)
}

func LoadRootOfTrustCertificate(path string) (PilaGeneralCertificate, error) {

	return nil, nil
}

type ASCertificateHandler struct {
	conn   *snet.Conn
	config *PilaConfig
}

func NewASCertificateHandler(config *PilaConfig) *ASCertificateHandler {
	return &ASCertificateHandler{config: config}
}

func (h *ASCertificateHandler) InitIfNecessary() error {
	if snet.DefNetwork == nil {
		log.Printf("snet.Init: lIA = %s, sciond path = \"%s\", dispatcher path = \"%s\"",
			h.config.lIA.String(), h.config.sciondPath, h.config.dispatcherPath)
		return snet.Init(h.config.lIA, h.config.sciondPath, h.config.dispatcherPath)
	}
	return nil
}

func (h *ASCertificateHandler) createASCertificateRequest(publicKey PublicKeyWithAlgorithm) ([]byte, error) {
	log.Println("createASCertificateRequest")
	publicKeyRaw, _ := GetPublicKeyRaw(publicKey)
	req := &cert_mgmt.PilaReq{
		SignedName: pilaASCertificateSignedName,
		EndpointIdentifier: cert_mgmt.HostInfo{
			Port: h.config.port,
			Addrs: struct {
				Ipv4 []byte
				Ipv6 []byte
			}{Ipv4: h.config.lAddr.Host.IP()}},
		RawPublicKey: publicKeyRaw}
	cpld, err := ctrl.NewCertMgmtPld(req, nil, nil)
	if err != nil {
		return nil, err
	}
	return cpld.PackPld()
}

// // Hack to use existing cert.Certificate & existing signing methods
// type EndpointIdentifierSubject struct {
// 	addr.IA
// 	stringRepresentation []byte
// }

// func (ei EndpointIdentifierSubject) MarshalText() ([]byte, error) {
// 	return stringRepresentation
// }

// func (ei EndpointIdentifierSubject) Eq(other EndpointIdentifierSubject) bool {
// 	// check type

// 	// check content
// 	....................
// }

// type PilaCertificate struct {
// 	cert.Certificate
// 	endpointIdentifierSubject EndpointIdentifierSubject
// 	signedNameComment string
// }

func (h *ASCertificateHandler) parseASCertificateReply(reply []byte) (*cert_mgmt.PilaRep, error) {
	signed, err := ctrl.NewSignedPldFromRaw(reply)
	if err != nil {
		return nil, errors.New("Unable to parse signed payload: " + err.Error())
	}

	//todo(cyrill): perform verification?
	// if signed.Sign != nil {
	// 	verifier := config.GetVerifier()
	// 	if err := ctrl.VerifySig(signed, verifier); err != nil {
	// 		return common.NewBasicError("Unable to verify signed payload", err, "addr", addr)
	// 	}
	// }

	cpld, err := signed.Pld()
	if err != nil {
		return nil, errors.New("Unable to parse ctrl payload: " + err.Error())
	}

	c, err := cpld.Union()
	if err != nil {
		return nil, errors.New("Unable to unpack ctrl union: " + err.Error())
	}
	switch c.(type) {
	case *cert_mgmt.Pld:
		pld, err := c.(*cert_mgmt.Pld).Union()
		if err != nil {
			return nil, errors.New("Unable to unpack cert_mgmt union: " + err.Error())
		}
		switch pld.(type) {
		case *cert_mgmt.PilaRep:
			return pld.(*cert_mgmt.PilaRep), nil
		default:
			return nil, fmt.Errorf("Wrong cert_mgmgt type (protoID=%s): %T", pld.ProtoId(), pld)
		}
	default:
		return nil, fmt.Errorf("Handler for cpld not implemented: ProtoID=%s", c.ProtoId())
	}
}

func (h *ASCertificateHandler) validateCertificate(endpointCert *cert.PilaCertificate, publicKey PublicKeyWithAlgorithm) error {
	publicKeyRaw, err := GetPublicKeyRaw(publicKey)
	if err != nil {
		return errors.New("Certificate cannot be validated: " + err.Error())
	}
	if !bytes.Equal(endpointCert.SubjectSignKey, publicKeyRaw) {
		return errors.New("Signing key is not identical")
	}
	//todo(cyrill): adjust for different certificate subject entities
	configEntity := cert.PilaCertificateEntity{Ipv4: h.config.lAddr.Host.IP()}
	if !configEntity.Eq(endpointCert.Subject) {
		localIP, _ := configEntity.MarshalText()
		remoteIP, _ := endpointCert.Subject.MarshalText()
		return errors.New("Local IP Address (" + string(localIP) + ") != endpointCert.Subject (" + string(remoteIP) + ")")
	}
	if pilaASCertificateSignedName != endpointCert.Comment {
		return errors.New("SignedName (" + pilaASCertificateSignedName + ") != Endpoint cert.Comment(" + endpointCert.Comment + ")")
	}
	//if endpointCert.Verify(subject PilaCertificateEntity, verifyKey common.RawBytes, signAlgo string)
	return nil
}

func (h *ASCertificateHandler) PilaRequestASCertificate(publicKey PublicKeyWithAlgorithm) (*cert.PilaChain, error) {
	if err := h.InitIfNecessary(); err != nil {
		return nil, err
	}

	log.Println("PilaRequestASCertificate: lAddr = " + h.config.lAddr.String() + ", csAddr = " + h.config.csAddr.String())
	if h.conn == nil {
		conn, err := snet.DialSCION("udp4", h.config.lAddr, h.config.csAddr)
		if err != nil {
			return nil, errors.New("Failed snet.DialSCION: " + err.Error())
		}
		h.conn = conn
	}

	req, err := h.createASCertificateRequest(publicKey)
	if err != nil {
		return nil, errors.New("Failed to create PILA AS certificate request: " + err.Error())
	}

	readBuffer := make([]byte, MaxResponseSizeInBytes)
	var numtries int64 = 0
	for numtries < MaxTries {
		_, err = h.conn.Write(req)
		if err != nil {
			return nil, errors.New("Failed to write req(size = " + strconv.Itoa(MaxResponseSizeInBytes) + "): " + err.Error())
		}

		err = h.conn.SetReadDeadline(time.Now().Add(h.config.certificateServerReadDeadline))
		if err != nil {
			return nil, errors.New("Failed to read PILA AS certificate response: " + err.Error())
		}

		n, err := h.conn.Read(readBuffer)
		if err != nil {
			// Do note return with error, retry up to MaxTries
			log.Println("Error reading AS cert response from certificate server (numtries=%d): %s", numtries, err.Error())
			numtries++
			continue
		}
		log.Println("Read PILA AS cert reply (" + strconv.Itoa(n) + "bytes)")
		repBuf := readBuffer[:n]

		// Remove read deadline
		// todo(cyrill): necessary?
		err = h.conn.SetReadDeadline(time.Time{})
		if err != nil {
			return nil, err
		}

		// Extract result
		reply, err := h.parseASCertificateReply(repBuf)
		if err != nil {
			return nil, err
		}

		//		log.Println("AS cert reply (size=" + strconv.Itoa(len(reply)) + ")")

		pilaChain, err := reply.PilaChain()
		if err != nil {
			return nil, err
		}

		jsonIssuer, err := pilaChain.Issuer.JSON(true)
		jsonLeaf, err := pilaChain.Leaf.JSON(true)
		jsonEndpoint, err := pilaChain.Endpoint.JSON(true)
		log.Println("issuer = " + string(jsonIssuer))
		log.Println("leaf = " + string(jsonLeaf))
		log.Println("endpoint = " + string(jsonEndpoint))

		if err := h.validateCertificate(pilaChain.Endpoint, publicKey); err != nil {
			return nil, errors.New("Failed to validate reply from certificate server: " + err.Error())
		}
		return pilaChain, nil
	}

	if numtries == MaxTries {
		return nil, fmt.Errorf("Error, could not receive a certificate server response, MaxTries attempted without success.")
	}

	panic("Should not reach here")
	return nil, nil
}

func PilaRequestRootOfTrustCertificate() (PilaGeneralCertificate, error) {
	return nil, nil
}

func (c *PilaConfig) PilaRequestSignature(m *Msg) error {
	addPilaTxtRecord(m, false, true, []byte{})
	//todo(cyrill): set/unset DO bit in client
	addPilaOptRecord(m, c.MaxUdpSize, false)
	return nil
}

func DebugPrint(msgName string, m *Msg) {
	log.Println("\n***** " + msgName + ": \n" + m.String() + "\n*****\n\n")
}

func GenerateKeyTag() uint16 {
	return 42
}

func (conf *PilaConfig) PilaSign(m *Msg, signalg SignerWithAlgorithm, peerIP net.IP) error {
	pub, err := GetPublicKeyWithAlgorithm(signalg)
	if err != nil {
		return errors.New("Failed to extract public key to send to the certificate server: " + err.Error())
	}
	h := NewASCertificateHandler(conf)
	//todo(cyrill) add cert to pila txt record
	chain, err := h.PilaRequestASCertificate(pub)
	if err != nil {
		return err
	}
	//todo(cyrill): adjust parameters
	sigrr := createPilaSIG(signalg.Algorithm(), GenerateKeyTag(), pilaSIGNameString)
	additionalInfo, err := sigrr.getAdditionalInfo(m.Request, Encode(peerIP))
	if err != nil {
		return errors.New("Failed to extract additional info from request")
	}
	log.Println(additionalInfo)

	jsonEncodedPilaChain, err := chain.JSON(false)
	if err != nil {
		return errors.New("Failed to create JSON encoding of PilaChain: " + err.Error())
	}
	addPilaTxtRecord(m, false, true, []byte(jsonEncodedPilaChain))

	signedMsgPacked, err := sigrr.pilaSignRR(signalg.Signer(), m, additionalInfo)
	if err != nil {
		return errors.New("Failed PILA signature: " + err.Error())
	}

	// testPacked, err := sigrr.Sign(signalg.Signer(), m)
	testPacked, err := m.Pack()
	test := new(Msg)
	test.Unpack(testPacked)
	DebugPrint("test", test)
	//signedMsg := new(Msg)
	if err := m.Unpack(signedMsgPacked); err != nil {
		return errors.New("Failed to unpack signed msg: " + err.Error())
	}
	//m = *signedMsg
	return nil
}

func (conf *PilaConfig) PilaVerify(m *Msg, original *Msg, signalg PublicKeyWithAlgorithm, remoteIp net.IP) error {
	// SIG and RRSIG implement interface RR
	sigrr, err := getPilaSIG(m)
	if err != nil {
		return errors.New("Error reading last SIG record from dns message: " + err.Error())
	}
	if sigrr == nil {
		return errors.New("No PILA SIG record available")
	}
	if signalg.Algorithm() != sigrr.Algorithm {
		return errors.New("Returned algrithm does not match expected algorithm")
	}

	// get PilaChain from txt record in m
	pilaTxt, err := getPilaTxtRecord(m)
	if err != nil {
		return errors.New("Failed to retrieve certificate chain from message: " + err.Error())
	}

	// extract PilaChain
	pilaChain, err := cert.PilaChainFromRaw(pilaTxt.CertificateChainRaw)
	if err != nil {
		return errors.New("Failed to parse PILA certificate chain: " + err.Error())
	}

	// verify pilachain using trc
	trc, err := conf.ReadTrc()
	if err := pilaChain.Verify(cert.PilaCertificateEntity{Ipv4: remoteIp}, trc); err != nil {
		return errors.New("Failed to verify PILA certificate chain: " + err.Error())
	}

	// get public key from leaf cert and set algorithm & base64 pubkey
	var algorithm uint8
	switch pilaChain.Endpoint.SignAlgorithm {
	case "ECDSAP256SHA256":
		algorithm = ECDSAP256SHA256
	case "ECDSAP384SHA384":
		algorithm = ECDSAP384SHA384
	}
	pubKeyBase64 := toBase64(pilaChain.Endpoint.SubjectSignKey)

	// Create verification context based on original message
	var originalRaw []byte
	original.PackBuffer(originalRaw)
	additionalInfo, err := sigrr.getAdditionalInfo(originalRaw, Encode(remoteIp))
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
	error := sigrr.pilaVerifyRR(key, buf, additionalInfo)
	return error
}

// encodes a ECDSA private/public key using pem encoding & x509 marshalling
func EncodeEcdsaKeys(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) (string, string) {
	x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

	x509EncodedPub, _ := x509.MarshalPKIXPublicKey(publicKey)
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})

	return string(pemEncoded), string(pemEncodedPub)
}

// decodes a pem encoded & x509 marshalled public/private key
func decodeEcdsaKeys(pemEncoded string, pemEncodedPub string) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	block, _ := pem.Decode([]byte(pemEncoded))
	x509Encoded := block.Bytes
	privateKey, _ := x509.ParseECPrivateKey(x509Encoded)

	blockPub, _ := pem.Decode([]byte(pemEncodedPub))
	x509EncodedPub := blockPub.Bytes
	genericPublicKey, _ := x509.ParsePKIXPublicKey(x509EncodedPub)
	publicKey := genericPublicKey.(*ecdsa.PublicKey)

	return privateKey, publicKey
}

func ReadKeys(priv string, pub string) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	privKey, err := ioutil.ReadFile(priv)
	if err != nil {
		panic(err)
	}
	pubKey, err := ioutil.ReadFile(pub)
	if err != nil {
		panic(err)
	}
	return decodeEcdsaKeys(string(privKey), string(pubKey))
}

func FromBase64(s []byte) (buf []byte, err error) {
	buflen := base64.StdEncoding.DecodedLen(len(s))
	buf = make([]byte, buflen)
	n, err := base64.StdEncoding.Decode(buf, s)
	buf = buf[:n]
	return
}

func createPilaSIG(algorithm uint8, keyTag uint16, signerName string) *SIG {
	now := uint32(time.Now().Unix())
	sigrr := new(SIG)
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
	sigrr.KeyTag = keyTag
	sigrr.SignerName = signerName
	//sigrr.Signature = "" default value
	domainNameLength, _ := PackDomainName(sigrr.SignerName, nil, 0, nil, false)
	signatureWireFormat, _ := FromBase64([]byte(sigrr.Signature))
	signatureWireLength := len(signatureWireFormat)
	sigrr.Header().Rdlength = 2 + 1 + 1 + 4 + 4 + 4 + 2 + uint16(domainNameLength) + uint16(signatureWireLength)
	return sigrr
}

func createPilaKEY(protocol uint8, algorithm uint8, publicKeyBase64 string) *KEY {
	log.Println("createPilaKey")
	key := new(KEY)
	key.Header().Name = pilaKEYNameString
	key.Header().Rrtype = TypeKEY
	key.Header().Class = ClassANY
	key.Flags = 0
	key.Protocol = protocol
	key.Algorithm = algorithm
	key.PublicKey = publicKeyBase64
	return key
}

func getPilaSIG(m *Msg) (*SIG, error) {
	rr := getLastExtraRecord(m, TypeSIG)
	if rr == nil {
		return nil, errors.New("No Extra TypeSIG record available")
	}
	sig, ok := rr.(*SIG)
	if !ok {
		return nil, errors.New("Last Extra record with type TypeSIG cannot be transformed into a SIG record")
	}
	if sig.SignerName != pilaSIGNameString {
		return nil, errors.New("Last Extra SIG record is not a PILA SIG record")
	}
	return rr.(*SIG), nil
}

type PilaTxtStruct struct {
	// Adds randomness to a request in order to prevent replay attacks
	Randomness []byte
	// A list of certificates used to authenticate this message from the root of
	// trust (TRC in case of SCION) to the certificate authenticating the IP
	// address of the server
	CertificateChainRaw []byte
}

type SourceIdentifier interface {
	Encode() []byte
}

// https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
func Encode(ip net.IP) []byte {
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

func combineTxtResources(txtStrings []string) string {
	var b strings.Builder
	for _, s := range txtStrings {
		b.Write([]byte(s))
	}
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

func addPilaOptRecord(m *Msg, maxUdpSize uint16, do bool) {
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

func addPilaTxtRecord(m *Msg, requestingSignature bool, providingSignature bool, certificateChainRaw []byte) error {
	var randomnessLength int
	if requestingSignature {
		randomnessLength = 8
	}
	txtContent, error := createPilaTxtRecord(randomnessLength, certificateChainRaw)
	if error != nil {
		return error
	}
	var rr RR
	//todo(cyrill): split content into different txt string records
	txtStringRecords, off := splitTxtResources(string(txtContent))
	if len(txtContent) != off {
		return fmt.Errorf("Couldn't fit certificate chain into txt record. Added %d of %d bytes", off, len(txtContent))
	}
	rr = &TXT{Hdr: RR_Header{Name: pilaTxtNameString, Rrtype: TypeTXT, Class: ClassINET, Ttl: 0}, Txt: txtStringRecords}
	m.Extra = append(m.Extra, rr)
	return nil
}

func getLastExtraRecord(m *Msg, typeCovered uint16) RR {
	for i := len(m.Extra) - 1; i >= 0; i-- {
		if m.Extra[i].Header().Rrtype == typeCovered {
			return m.Extra[i]
		}
	}
	return nil
}

func getPilaTxtRecord(m *Msg) (*PilaTxtStruct, error) {
	// No additional records
	if len(m.Extra) == 0 {
		return nil, errors.New("No additional resource records present")
	}

	rr := getLastExtraRecord(m, TypeTXT).(*TXT)
	if rr == nil {
		return nil, errors.New("No txt records present")
	}

	// not pila txt record
	if rr.Header().Name != pilaTxtNameString {
		return nil, errors.New("Last txt record is not: " + pilaTxtNameString + " txt record")
	}

	if len(rr.Txt) == 0 {
		return nil, errors.New("Empty txt record")
	}
	txtStringsCombined := combineTxtResources(rr.Txt)
	var s PilaTxtStruct
	if _, err := asn1.Unmarshal([]byte(txtStringsCombined), &s); err != nil {
		return nil, errors.New("ASN1 Unmarshal failed: " + err.Error())
	}
	return &s, nil
}

func createPilaTxtRecord(randomnessLength int, certificatesRaw []byte) ([]byte, error) {
	randValue := randofsize(randomnessLength)
	//todo(cyrill): randomness length
	txtStruct := PilaTxtStruct{Randomness: randValue, CertificateChainRaw: certificatesRaw}
	txtEncoded, error := asn1.Marshal(txtStruct)
	if error != nil {
		return nil, errors.New("Cannot marshal PilaTxtStruct")
	}
	return txtEncoded, nil
}

func randofsize(size int) []byte {
	//todo(cyrill): implement random function
	var result []byte
	start := byte('a')
	for i := 0; i < size; i++ {
		result = append(result, start)
		start++
	}
	return result
}

func (rr *SIG) getAdditionalInfo(request []byte, srcIdentifier []byte) ([]byte, error) {
	hash, ok := AlgorithmToHash[rr.Algorithm]
	if !ok {
		return nil, ErrAlg
	}

	hasher := hash.New()
	// Include the request if possible
	hasher.Write(request)

	// Include the endpoint identifier to inhibit source address spoofing
	hasher.Write(srcIdentifier)

	return hasher.Sum(nil), nil
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

func LogSIG(data []byte, lengthHeaderName int, lengthSignerName int, totalLength int) string {
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

// Sign signs a Msg. It fills the signature with the appropriate data.
// The SIG record should have the SignerName, KeyTag, Algorithm, Inception
// and Expiration set.
func (rr *SIG) pilaSignRR(k crypto.Signer, m *Msg, additionalInfo []byte) ([]byte, error) {
	if k == nil {
		return nil, ErrPrivKey
	}
	if rr.KeyTag == 0 || len(rr.SignerName) == 0 || rr.Algorithm == 0 {
		log.Println(strconv.FormatUint(uint64(rr.KeyTag), 10))
		log.Println(rr.SignerName)
		log.Println(strconv.FormatUint(uint64(rr.Algorithm), 10))
		return nil, ErrKey
	}
	rr.Header().Rrtype = TypeSIG
	rr.Header().Class = ClassANY
	rr.Header().Ttl = 0
	rr.Header().Name = "."
	rr.OrigTtl = 0
	rr.TypeCovered = 0
	rr.Labels = 0

	// // Testing SIG pack and unpack methods
	// testbuf := make([]byte, 1000)
	// if _, err := rr.pack(testbuf, 0, nil, false); err != nil {
	// 	log.Println("Error packing TEST SIG: " + err.Error())
	// }
	// header, offTest, _, err := unpackHeader(testbuf, 0)
	// if err != nil {
	// 	log.Println("Error unpacking TEST SIG header: " + err.Error())
	// }
	// testUnpacked, offTest, err := unpackSIG(header, testbuf, offTest)
	// if err != nil {
	// 	log.Println("Error unpacking TEST SIG: " + err.Error())
	// }
	// log.Println("SIG packing/unpacking: DeepEqual() = " + strconv.FormatBool(reflect.DeepEqual(rr, testUnpacked)))

	log.Printf("m.Len() = %d, rr.len() = %d", m.Len(), rr.len())
	buf := make([]byte, m.Len()+rr.len())
	mbuf, err := m.PackBuffer(buf)
	log.Println("test1")
	if err != nil {
		return nil, err
	}
	log.Println("test2")
	if &buf[0] != &mbuf[0] {
		return nil, ErrBuf
	}
	off, err := PackRR(rr, buf, len(mbuf), nil, false)
	log.Println("test3")
	if err != nil {
		return nil, err
	}
	buf = buf[:off:cap(buf)]

	hash, ok := AlgorithmToHash[rr.Algorithm]
	log.Println("test4")
	if !ok {
		return nil, ErrAlg
	}

	hasher := hash.New()
	// Write SIG rdata
	hasher.Write(buf[len(mbuf)+1+2+2+4+2:])

	// log.Print("buf after content (excluding SIGRR): ")
	// log.Println(buf[len(mbuf) : len(mbuf)+1+2+2+4+2])

	// Write message
	hasher.Write(buf[:len(mbuf)])
	// Write additional info
	hasher.Write(additionalInfo)

	signature, err := sign(k, hasher.Sum(nil), hash, rr.Algorithm)
	if err != nil {
		return nil, err
	}

	//log.Println("Before sign: " + LogSIG(buf[len(mbuf):], 15, 15, len(buf)-len(mbuf)))

	rr.Signature = toBase64(signature)

	buf = append(buf, signature...)
	if len(buf) > int(^uint16(0)) {
		return nil, ErrBuf
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

	//log.Println("After sign: " + LogSIG(buf[len(mbuf):], 15, 15, len(buf)-len(mbuf)))

	return buf, nil
}

// Verify validates the message buf using the key k.
// It's assumed that buf is a valid message from which rr was unpacked.
func (rr *SIG) pilaVerifyRR(k *KEY, buf []byte, additionalInfo []byte) error {
	log.Println("pilaVerifyRR: len(buf) = " + strconv.Itoa(len(buf)) + ", len(addInfo) = " + strconv.Itoa(len(additionalInfo)))

	if k == nil {
		return ErrKey
	}
	if rr.KeyTag == 0 || len(rr.SignerName) == 0 || rr.Algorithm == 0 {
		return ErrKey
	}

	var hash crypto.Hash
	switch rr.Algorithm {
	case DSA, RSASHA1:
		hash = crypto.SHA1
	case RSASHA256, ECDSAP256SHA256:
		hash = crypto.SHA256
	case ECDSAP384SHA384:
		hash = crypto.SHA384
	case RSASHA512:
		hash = crypto.SHA512
	default:
		return ErrAlg
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
		_, offset, err = UnpackDomainName(buf, offset)
		if err != nil {
			return err
		}
		// Skip past Type and Class
		offset += 2 + 2
	}
	for i := uint16(1); i < anc+auc+adc && offset < buflen; i++ {
		_, offset, err = UnpackDomainName(buf, offset)
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
		return &Error{err: "overflowing unpacking signed message"}
	}

	// offset should be just prior to SIG
	bodyend := offset
	// owner name SHOULD be root
	_, offset, err = UnpackDomainName(buf, offset)
	if err != nil {
		return err
	}
	// Skip Type, Class, TTL, RDLen
	offset += 2 + 2 + 4 + 2
	sigstart := offset
	// Skip Type Covered, Algorithm, Labels, Original TTL
	offset += 2 + 1 + 1 + 4
	if offset+4+4 >= buflen {
		return &Error{err: "overflow unpacking signed message"}
	}
	expire := binary.BigEndian.Uint32(buf[offset:])
	offset += 4
	incept := binary.BigEndian.Uint32(buf[offset:])
	offset += 4
	now := uint32(time.Now().Unix())
	if now < incept || now > expire {
		return ErrTime
	}
	// Skip key tag
	offset += 2
	var signername string
	signername, offset, err = UnpackDomainName(buf, offset)
	if err != nil {
		return err
	}
	log.Println("Unpacked everything")
	// If key has come from the DNS name compression might
	// have mangled the case of the name
	if strings.ToLower(signername) != strings.ToLower(k.Header().Name) {
		return &Error{err: "signer name doesn't match key name"}
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

	log.Println("k.Algorithm = "+strconv.FormatUint(uint64(k.Algorithm), 10)+", ECDSAP256SHA256 = "+strconv.FormatUint(uint64(ECDSAP256SHA256), 10), ", ECDSAP384SHA384 = "+strconv.FormatUint(uint64(ECDSAP384SHA384), 10))

	hashed := hasher.Sum(nil)
	sig := buf[sigend:]
	switch k.Algorithm {
	case DSA:
		pk := k.publicKeyDSA()
		sig = sig[1:]
		r := big.NewInt(0)
		r.SetBytes(sig[:len(sig)/2])
		s := big.NewInt(0)
		s.SetBytes(sig[len(sig)/2:])
		if pk != nil {
			if dsa.Verify(pk, hashed, r, s) {
				return nil
			}
			return ErrSig
		}
	case RSASHA1, RSASHA256, RSASHA512:
		pk := k.publicKeyRSA()
		if pk != nil {
			return rsa.VerifyPKCS1v15(pk, hash, hashed, sig)
		}
	case ECDSAP256SHA256, ECDSAP384SHA384:
		pk := k.publicKeyECDSA()
		r := big.NewInt(0)
		r.SetBytes(sig[:len(sig)/2])
		s := big.NewInt(0)
		s.SetBytes(sig[len(sig)/2:])
		log.Println("ECDSA: X = " + pk.X.String() + ", Y = " + pk.Y.String())
		if pk != nil {
			if ecdsa.Verify(pk, hashed, r, s) {
				return nil
			}
			return ErrSig
		}
	}
	return ErrKeyAlg
}
