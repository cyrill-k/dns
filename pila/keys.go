package pila

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"path"

	"github.com/cyrill-k/dns"
	"github.com/scionproto/scion/go/lib/crypto/cert"
)

type SignerWithAlgorithm interface {
	Signer() crypto.Signer
	Algorithm() uint8
}

type PublicKeyWithAlgorithm interface {
	PublicKeyBase64() string
	Algorithm() uint8
}

func GetPublicKeyWithAlgorithm(signalg SignerWithAlgorithm) (PublicKeyWithAlgorithm, error) {
	switch signalg.Signer().(type) {
	case *ecdsa.PrivateKey:
		return NewECDSAPublicKey(signalg.Signer().Public().(*ecdsa.PublicKey)), nil
	}
	return nil, errors.New("Unsupported private key cannot be converted into public key")
}

func GetPublicKeyRaw(pubKey PublicKeyWithAlgorithm) ([]byte, error) {
	return u.FromBase64([]byte(pubKey.PublicKeyBase64()))
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
	copy(buffer[:lenbuf/2], pub.PublicKey.X.Bytes())
	copy(buffer[lenbuf/2:], pub.PublicKey.Y.Bytes())
	return u.ToBase64(buffer)
}

func (pub *ECDSAPublicKey) Algorithm() uint8 {
	return pub.AlgorithmValue
}

func NewECDSASigner(privateKey *ecdsa.PrivateKey) SignerWithAlgorithm {
	var algorithm uint8
	switch privateKey.Curve {
	case elliptic.P256():
		algorithm = dns.ECDSAP256SHA256
	case elliptic.P384():
		algorithm = dns.ECDSAP384SHA384
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
		algorithm = dns.ECDSAP256SHA256
	case elliptic.P384():
		algorithm = dns.ECDSAP384SHA384
	}
	signer := ECDSAPublicKey{
		PublicKey:      publicKey,
		AlgorithmValue: algorithm,
	}
	return &signer
}

func ReadKeys(priv string, pub string) (privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) {
	privKey, err := ioutil.ReadFile(priv)
	if err == nil {
		privateKey = DecodeEcdsaPrivateKey(privKey)
	}
	pubKey, err := ioutil.ReadFile(pub)
	if err == nil {
		publicKey = DecodeEcdsaPublicKey(pubKey)
	}
	return
}

// encodes a ECDSA private/public key using pem encoding & x509 marshalling
func EncodeEcdsaPrivateKey(privateKey *ecdsa.PrivateKey) (pemEncoded []byte) {
	x509Encoded, err := x509.MarshalECPrivateKey(privateKey)
	if err == nil {
		pemEncoded = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})
	}
	return
}

// encodes a ECDSA private/public key using pem encoding & x509 marshalling
func EncodeEcdsaPublicKey(publicKey *ecdsa.PublicKey) (pemEncoded []byte) {
	x509Encoded, err := x509.MarshalPKIXPublicKey(publicKey)
	if err == nil {
		pemEncoded = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509Encoded})
	}
	return
}

// decodes a pem encoded & x509 marshalled public/private key
func DecodeEcdsaPrivateKey(pemEncoded []byte) (privateKey *ecdsa.PrivateKey) {
	block, _ := pem.Decode(pemEncoded)
	if block != nil {
		x509Encoded := block.Bytes
		var err error
		privateKey, err = x509.ParseECPrivateKey(x509Encoded)
		if err != nil {
			privateKey = nil
		}
	}
	return
}

// decodes a pem encoded & x509 marshalled public/private key
func DecodeEcdsaPublicKey(pemEncoded []byte) (publicKey *ecdsa.PublicKey) {
	block, _ := pem.Decode(pemEncoded)
	if block != nil {
		x509Encoded := block.Bytes
		genericPublicKey, err := x509.ParsePKIXPublicKey(x509Encoded)
		if err == nil {
			// don't panic if wrong type, just return nil
			publicKey, _ = genericPublicKey.(*ecdsa.PublicKey)
		}
	}
	return
}

// encodes a ECDSA private/public key using pem encoding & x509 marshalling
func EncodeEcdsaKeys(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) ([]byte, []byte) {
	return EncodeEcdsaPrivateKey(privateKey), EncodeEcdsaPublicKey(publicKey)
}

// decodes a pem encoded & x509 marshalled public/private key
func DecodeEcdsaKeys(pemEncoded []byte, pemEncodedPub []byte) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	return DecodeEcdsaPrivateKey(pemEncoded), DecodeEcdsaPublicKey(pemEncodedPub)
}

// Returns a default private, public key pair and a corresponsing PILA certificate chain
func ReadKeysAndCertChainFromFolder(root string) (priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey, chain *cert.PilaChain) {
	priv, pub = ReadKeys(path.Join(root, "priv.pem"), path.Join(root, "pub.pem"))
	chain, _ = ReadPilaCertificateChain(path.Join(root, "pilachain"))
	return
}
