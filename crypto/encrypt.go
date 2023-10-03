package crypto

import (
	"errors"

	"github.com/fainc/go-crypto/aes"
	"github.com/fainc/go-crypto/gm"
	"github.com/fainc/go-crypto/rsa"
)

// EasyEncrypt 数据加密便捷代理方法,options支持自定义AES IV,支持algo列表: algorithm.SupportedAlgo
func EasyEncrypt(algo, secret, data string, hex bool, options ...string) (encrypted string, err error) {
	option := ""
	if len(options) == 1 && options[0] != "" {
		option = options[0]
	}
	switch algo {
	case "SM2_C1C3C2":
		return gm.Sm2().Encrypt(secret, data, 0, hex)
	case "SM2_C1C2C3":
		return gm.Sm2().Encrypt(secret, data, 1, hex)
	case "SM2_ASN1":
		return gm.Sm2().EncryptAsn1(secret, data, hex)
	case "SM4_ECB":
		return gm.Sm4().Encrypt(secret, data, "ECB", hex)
	case "SM4_CBC":
		return gm.Sm4().Encrypt(secret, data, "CBC", hex)
	case "SM4_CFB":
		return gm.Sm4().Encrypt(secret, data, "CFB", hex)
	case "SM4_OFB":
		return gm.Sm4().Encrypt(secret, data, "OFB", hex)
	case "RSA_PKCS1":
		return rsa.EncryptPKCS1(secret, data, hex)
	case "AES_CBC_PKCS7":
		return aes.CBC().EncryptPKCS7(secret, data, option)
	default:
		return "", errors.New("unsupported algo")
	}
}
