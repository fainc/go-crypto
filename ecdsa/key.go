package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/fainc/go-crypto/format"
)

var (
	errKeyMustBePEMEncoded = errors.New("invalid key: Key must be a PEM encoded PKCS1 or PKCS8 key")
	errNotECPublicKey      = errors.New("key is not a valid ECDSA public key")
	errNotECPrivateKey     = errors.New("key is not a valid ECDSA private key")
)

func GenKey() (pri, pub *format.RetFormatter, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}
	priDer, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return
	}
	pubDer, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return
	}
	return format.NewRet(priDer), format.NewRet(pubDer), nil
}

func ParsePrivateKeyFromDer(priDer []byte) (*ecdsa.PrivateKey, error) {
	var err error
	// Parse the key
	var parsedKey interface{}
	if parsedKey, err = x509.ParseECPrivateKey(priDer); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(priDer); err != nil {
			return nil, err
		}
	}

	var pkey *ecdsa.PrivateKey
	var ok bool
	if pkey, ok = parsedKey.(*ecdsa.PrivateKey); !ok {
		return nil, errNotECPrivateKey
	}

	return pkey, nil
}
func ParsePublicKeyFromDer(pubDer []byte) (*ecdsa.PublicKey, error) {
	var err error
	// Parse the key
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKIXPublicKey(pubDer); err != nil {
		if cert, err := x509.ParseCertificate(pubDer); err == nil {
			parsedKey = cert.PublicKey
		} else {
			return nil, err
		}
	}

	var pkey *ecdsa.PublicKey
	var ok bool
	if pkey, ok = parsedKey.(*ecdsa.PublicKey); !ok {
		return nil, errNotECPublicKey
	}

	return pkey, nil
}

func PrivateKeyToPem(priDer []byte) (priPem string, err error) {
	priBlock := pem.Block{
		Type:  "ECDSA Private Key",
		Bytes: priDer,
	}
	pri := pem.EncodeToMemory(&priBlock)
	if pri == nil {
		err = errors.New("encode pem failed")
		return
	}
	priPem = string(pri)
	return
}

func PublicKeyToPem(pubDer []byte) (pubPem string, err error) {
	pubBlock := pem.Block{
		Type:  "ECDSA Public Key",
		Bytes: pubDer,
	}
	pub := pem.EncodeToMemory(&pubBlock)
	if pub == nil {
		err = errors.New("encode pem failed")
		return
	}
	pubPem = string(pub)
	return
}

func PrivatePemToKey(priPem string) (pri *ecdsa.PrivateKey, err error) {
	var priBlock *pem.Block
	if priBlock, _ = pem.Decode([]byte(priPem)); priBlock == nil {
		return nil, errKeyMustBePEMEncoded
	}
	pri, err = ParsePrivateKeyFromDer(priBlock.Bytes)
	return
}

func PublicPemToKey(pubPem string) (pri *ecdsa.PublicKey, err error) {
	var pubBlock *pem.Block
	if pubBlock, _ = pem.Decode([]byte(pubPem)); pubBlock == nil {
		return nil, errKeyMustBePEMEncoded
	}
	pri, err = ParsePublicKeyFromDer(pubBlock.Bytes)
	return
}
