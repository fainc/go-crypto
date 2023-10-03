package crypto

import (
	"errors"

	"github.com/fainc/go-crypto/aes"
	"github.com/fainc/go-crypto/gm"
	"github.com/fainc/go-crypto/rsa"
)

// EasyDecrypt 数据解密便捷代理方法 option可传证书密码或自定义IV,algo 支持algo列表 algorithm.SupportedAlgo
func EasyDecrypt(algo, key, data string, hex bool, options ...string) (decrypted string, err error) {
	option := ""
	if len(options) == 1 && options[0] != "" {
		option = options[0]
	}
	switch algo {
	case "SM2_C1C3C2":
		return gm.Sm2().Decrypt(key, option, data, 0, hex)
	case "SM2_C1C2C3":
		return gm.Sm2().Decrypt(key, option, data, 1, hex)
	case "SM2_ASN1":
		return gm.Sm2().DecryptAsn1(key, option, data, hex)
	case "SM4_ECB":
		return gm.Sm4().Decrypt(key, data, "ECB", hex)
	case "SM4_CBC":
		return gm.Sm4().Decrypt(key, data, "CBC", hex)
	case "SM4_CFB":
		return gm.Sm4().Decrypt(key, data, "CFB", hex)
	case "SM4_OFB":
		return gm.Sm4().Decrypt(key, data, "OFB", hex)
	case "RSA_PKCS1":
		return rsa.DecryptPKCS1(key, data, hex)
	case "AES_CBC_PKCS7":
		return aes.CBC().DecryptPKCS7(key, data, option)
	default:
		return "", errors.New("unsupported algo")
	}
}
