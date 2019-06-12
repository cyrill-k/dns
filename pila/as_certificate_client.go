package pila

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"strconv"
	"time"

	"github.com/scionproto/scion/go/lib/crypto/cert"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/snet"
)

const (
	pilaASCertificateSignedName                        = "PILA CERTIFICATE"
	pilaIPv4                    EndpointIdentifierType = 1
	pilaIPv6                    EndpointIdentifierType = 2
	pilaScion                   EndpointIdentifierType = 100 // temporary assignment
	MaxTries                                           = 3
	MaxResponseSizeInBytes                             = 10000
)

type EndpointIdentifier interface {
	MarshalText() ([]byte, error)
}

type EndpointIdentifierType int

type ASCertificateHandler struct {
	conn   *snet.Conn
	config *PilaConfig
}

func ReadPilaCertificateChain(p string) (chain *cert.PilaChain, err error) {
	var chainRaw []byte
	chainRaw, err = ioutil.ReadFile(p)
	if err != nil {
		return
	}
	chain, err = cert.PilaChainFromRaw([]byte(chainRaw))
	return
}

func NewASCertificateHandler(config *PilaConfig) *ASCertificateHandler {
	return &ASCertificateHandler{config: config}
}

func (h *ASCertificateHandler) initIfNecessary() error {
	if snet.DefNetwork == nil {
		return snet.Init(h.config.lIA, h.config.sciondPath, h.config.dispatcherPath)
	}
	return nil
}

func (h *ASCertificateHandler) createASCertificateRequest(publicKey PublicKeyWithAlgorithm) ([]byte, error) {
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
	if err := h.initIfNecessary(); err != nil {
		return nil, err
	}

	log.Println("[ASCertificateClient] PilaRequestASCertificate(): lAddr = " + h.config.lAddr.String() + ", csAddr = " + h.config.csAddr.String())
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
			log.Printf("[ASCertificateClient] Error reading AS certificate response from certificate server (try#=%d): %s\n", numtries, err.Error())
			numtries++
			continue
		}
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

		pilaChain, err := reply.PilaChain()
		if err != nil {
			return nil, err
		}

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
