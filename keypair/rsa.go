package keypair

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"

	"github.com/fainc/go-crypto/format"
)

// GenRSAKeyPair 生成 RSA 密钥对 建议 2048 bits
func GenRSAKeyPair(bits int) (rsaKeyPair KeyPair, err error) {
	rsaKeyPair = KeyPair{}
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return
	}
	privateKeyPKCS8, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return
	}
	rsaKeyPair.Private = format.NewRet(privateKeyPKCS8)
	publicPKIX, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	rsaKeyPair.Public = format.NewRet(publicPKIX)
	return
}
