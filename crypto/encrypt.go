package crypto

import (
	"errors"

	"github.com/fainc/go-crypto/aes"
	"github.com/fainc/go-crypto/gm"
	"github.com/fainc/go-crypto/rsa"
)

// Encrypt 数据加密便捷代理方法
func Encrypt(algo, key, data string, hex bool) (encrypted string, err error) {
	switch algo {
	case "SM2_C1C3C2":
		return gm.Sm2().Encrypt(key, data, 0, hex)
	case "SM2_C1C2C3":
		return gm.Sm2().Encrypt(key, data, 1, hex)
	case "SM2_ASN1":
		return gm.Sm2().EncryptAsn1(key, data, hex)
	case "SM4_ECB":
		return gm.Sm4().Encrypt(key, data, "ECB", hex)
	case "SM4_CBC":
		return gm.Sm4().Encrypt(key, data, "CBC", hex)
	case "SM4_CFB":
		return gm.Sm4().Encrypt(key, data, "CFB", hex)
	case "SM4_OFB":
		return gm.Sm4().Encrypt(key, data, "CFB", hex)
	case "RSA_PKCS1":
		return rsa.EncryptPKCS1(key, data, hex)
	case "AES_CBC_PKCS7":
		return aes.CBC().EncryptPKCS7(key, data)
	default:
		return "", errors.New("unsupported algo")
	}
}
