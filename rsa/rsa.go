package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"

	"github.com/fainc/go-crypto/format"
)

func gen(bits int) (x509PrivateKey, x509PublicKey []byte, err error) {
	// 生成私钥文件
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return
	}
	// 通过x509标准将得到的ras私钥序列化为 ASN.1 的 DER 编码字符串
	x509PrivateKey = x509.MarshalPKCS1PrivateKey(privateKey)
	// X509对公钥编码
	x509PublicKey, err = x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	return
}

// Generate 生成RSA PKCS1 密钥对 不带格式化 解密使用时需要先调用Base64ToPem转换格式
func Generate(bits int) (pri, pub string, err error) {
	x509PrivateKey, X509PublicKey, err := gen(bits)
	pri = base64.StdEncoding.EncodeToString(x509PrivateKey)
	pub = base64.StdEncoding.EncodeToString(X509PublicKey)
	return
}

// GenerateFormat 生成RSA PKCS1 密钥对 带格式化
func GenerateFormat(bits int) (pri string, pub string, err error) {
	x509PrivateKey, X509PublicKey, err := gen(bits)
	if err != nil {
		return
	}
	pri = format.PemFormat(x509PrivateKey, "RSA PRIVATE KEY")
	pub = format.PemFormat(X509PublicKey, "RSA PUBLIC KEY")
	return
}

// Base64ToPem base64 未格式化密钥转pem格式 t = RSA PUBLIC KEY \ RSA PRIVATE KEY
func Base64ToPem(b, t string) (priPem string) {
	d, _ := base64.StdEncoding.DecodeString(b)
	return format.PemFormat(d, t)
}

// EncryptPKCS1 PKCS1 加密 ,PKCS8证书 需要先转换格式
func EncryptPKCS1(pub, plainText string, returnHex bool) (cipherTextStr string, err error) {
	block, _ := pem.Decode([]byte(pub)) // 解码
	if block == nil {
		err = errors.New("public key error")
		return
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		err = errors.New("public key parse failed")
		return
	}
	// 断言类型转换
	pubKey := pubInterface.(*rsa.PublicKey)

	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, []byte(plainText))
	if err != nil {
		err = errors.New("rsa encrypt failed")
		return
	}
	return format.ResHandler(cipherText, returnHex, false), nil
}

// DecryptPKCS1 PKCS1 解密 ,PKCS8证书 需要先转换格式
func DecryptPKCS1(pri, ciphertext string, isHex bool) (res string, err error) {
	block, _ := pem.Decode([]byte(pri))
	if block == nil {
		err = errors.New("private key error")
		return
	}
	// 解析PKCS1格式的私钥
	priKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		err = errors.New("private key parse failed")
		return
	}
	// 解密
	var decodeString []byte
	if isHex {
		decodeString, err = hex.DecodeString(ciphertext)
		if err != nil {
			return
		}
	} else {
		decodeString, err = base64.StdEncoding.DecodeString(ciphertext)
		if err != nil {
			return
		}
	}

	b, err := rsa.DecryptPKCS1v15(rand.Reader, priKey, decodeString)
	if err != nil {
		err = errors.New("rsa decrypt failed")
		return
	}
	return string(b), nil
}
