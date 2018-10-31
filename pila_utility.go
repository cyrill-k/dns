package dns

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"

	"golang.org/x/crypto/ed25519"
)

type PilaUtility struct{}

func (*PilaUtility) PackString(s string, msg []byte, off int) (int, error) {
	return packString(s, msg, off)
}

func (*PilaUtility) FromBase64(s []byte) (buf []byte, err error) {
	return fromBase64(s)
}

func (*PilaUtility) ToBase64(b []byte) string { return toBase64(b) }

func (*PilaUtility) PublicKeyRSA(k *DNSKEY) *rsa.PublicKey {
	return k.publicKeyRSA()
}

func (*PilaUtility) PublicKeyECDSA(k *DNSKEY) *ecdsa.PublicKey {
	return k.publicKeyECDSA()
}

func (*PilaUtility) PublicKeyDSA(k *DNSKEY) *dsa.PublicKey {
	return k.publicKeyDSA()
}

func (*PilaUtility) PublicKeyED25519(k *DNSKEY) ed25519.PublicKey {
	return k.publicKeyED25519()
}

func (*PilaUtility) Len(rr *SIG) int {
	return rr.len()
}
