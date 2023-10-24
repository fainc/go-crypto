package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"github.com/fainc/go-crypto/format"
)

type rsaEncCrypto struct {
	publicKey *rsa.PublicKey
}
type rsaDecCrypto struct {
	privateKey *rsa.PrivateKey
}

// NewPublic RSA 公钥操作，支持加密和验签，密钥使用 der base64
func NewPublic(public string) *rsaEncCrypto {
	var pub *rsa.PublicKey
	block, err := base64.StdEncoding.DecodeString(public) // 解码
	if err != nil || block == nil {
		panic("public key error")
	}
	parsedKey, err := x509.ParsePKIXPublicKey(block)
	if err != nil {
		panic(err.Error())
	}
	var ok bool
	if pub, ok = parsedKey.(*rsa.PublicKey); !ok {
		panic(errors.New("not rsa public key"))
	}
	return &rsaEncCrypto{pub}
}

// NewPrivate 私钥操作，支持解密和加签,密钥使用 der base64
func NewPrivate(private string) *rsaDecCrypto {
	var pri *rsa.PrivateKey
	block, err := base64.StdEncoding.DecodeString(private) // 解码
	if err != nil || block == nil {
		panic("public key error")
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(block)
	if err != nil {
		panic(err.Error())
	}
	var ok bool
	if pri, ok = parsedKey.(*rsa.PrivateKey); !ok {
		panic(errors.New("not rsa private key"))
	}
	return &rsaDecCrypto{pri}
}

// Encrypt PKCS1（常见默认填充） 加密 ,使用 PKIX 公钥
func (rec *rsaEncCrypto) Encrypt(plainText string) (f *format.RetFormatter, err error) {
	if rec.publicKey == nil {
		return nil, errors.New("public key error")
	}
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, rec.publicKey, []byte(plainText))
	if err != nil {
		err = errors.New("rsa encrypt failed")
		return
	}
	return format.NewRet(cipherText), nil
}

// DecryptWithFormat 格式转换解密实用方法，支持常见的 hexString 和 base64 ，isHex 为 true 则转换 hexString ，为 false 则转换 base64
func (rec *rsaDecCrypto) DecryptWithFormat(cipherText string, isHex bool) (result string, err error) {
	var src []byte
	if isHex {
		src, err = hex.DecodeString(cipherText)
	} else {
		src, err = base64.StdEncoding.DecodeString(cipherText)
	}
	if err != nil {
		return
	}
	plainText, err := rec.Decrypt(src)
	if err != nil {
		return
	}
	return string(plainText), nil
}

// Decrypt PKCS1 解密 ,使用 PKCS8 私钥 PKCS1格式需要先转换为PKCS8
func (rec *rsaDecCrypto) Decrypt(cipherText []byte) (res []byte, err error) {
	if rec.privateKey == nil {
		return nil, errors.New("private key error")
	}
	res, err = rsa.DecryptPKCS1v15(rand.Reader, rec.privateKey, cipherText)
	return
}
