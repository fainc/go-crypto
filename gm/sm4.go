package gm

import (
	"encoding/hex"
	"errors"

	"github.com/tjfoc/gmsm/sm4"

	"github.com/fainc/go-crypto/format"
)

type sm4Crypto struct {
	key []byte
}

func NewSm4(key string) *sm4Crypto {
	return &sm4Crypto{[]byte(key)}
}
func (rec *sm4Crypto) operate(data []byte, mode string, isEncrypt bool) (out []byte, err error) {
	switch mode {
	case "ECB":
		out, err = sm4.Sm4Ecb(rec.key, data, isEncrypt)
	case "CBC":
		out, err = sm4.Sm4Cbc(rec.key, data, isEncrypt)
	case "CFB":
		out, err = sm4.Sm4CFB(rec.key, data, isEncrypt)
	case "OFB":
		out, err = sm4.Sm4OFB(rec.key, data, isEncrypt)
	default:
		err = errors.New("unsupported mode：" + mode)
	}
	return
}
func (rec *sm4Crypto) Encrypt(plainText, mode string) (f *format.RetFormatter, err error) {
	if plainText == "" {
		err = errors.New("plain text can't be empty")
		return
	}
	out, err := rec.operate([]byte(plainText), mode, true)
	if err != nil {
		return
	}
	return format.NewRet(out), nil
}

func (rec *sm4Crypto) DecryptWithFormat(cipherTextHex string, mode string) (result string, err error) {
	cipherText, err := hex.DecodeString(cipherTextHex)
	if err != nil {
		return
	}
	plainText, err := rec.Decrypt(cipherText, mode)
	if err != nil {
		return
	}
	return string(plainText), nil
}
func (rec *sm4Crypto) Decrypt(cipherText []byte, mode string) (plainText []byte, err error) {
	plainText, err = rec.operate(cipherText, mode, false)
	if err != nil {
		return
	}
	if plainText == nil {
		err = errors.New("decrypted failed")
		return
	}
	return
}
