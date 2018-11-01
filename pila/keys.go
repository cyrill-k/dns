package pila

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"

	"github.com/cyrill-k/dns"
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
	log.Printf("get pub key: %T\n", signalg)
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

func ReadKeys(priv string, pub string) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	privKey, err := ioutil.ReadFile(priv)
	if err != nil {
		panic(err)
	}
	pubKey, err := ioutil.ReadFile(pub)
	if err != nil {
		panic(err)
	}
	return DecodeEcdsaKeys(string(privKey), string(pubKey))
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
func DecodeEcdsaKeys(pemEncoded string, pemEncodedPub string) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	block, _ := pem.Decode([]byte(pemEncoded))
	x509Encoded := block.Bytes
	privateKey, _ := x509.ParseECPrivateKey(x509Encoded)

	blockPub, _ := pem.Decode([]byte(pemEncodedPub))
	x509EncodedPub := blockPub.Bytes
	genericPublicKey, _ := x509.ParsePKIXPublicKey(x509EncodedPub)
	publicKey := genericPublicKey.(*ecdsa.PublicKey)

	return privateKey, publicKey
}

// ***** private dns functions needed in PILA
