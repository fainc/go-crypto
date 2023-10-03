package gm

import (
	"encoding/base64"
	"encoding/hex"
	"errors"

	"github.com/tjfoc/gmsm/sm4"

	"github.com/fainc/go-crypto/format"
)

type sm4Crypto struct {
}

func Sm4() *sm4Crypto {
	return &sm4Crypto{}
}
func (rec *sm4Crypto) operate(key, data []byte, mode string, isEncrypt bool) (out []byte, err error) {
	switch mode {
	case "ECB":
		out, err = sm4.Sm4Ecb(key, data, isEncrypt)
	case "CBC":
		out, err = sm4.Sm4Cbc(key, data, isEncrypt)
	case "CFB":
		out, err = sm4.Sm4CFB(key, data, isEncrypt)
	case "OFB":
		out, err = sm4.Sm4OFB(key, data, isEncrypt)
	default:
		err = errors.New("unsupported mode：" + mode)
	}
	return
}
func (rec *sm4Crypto) Encrypt(key, data, mode string, returnHex bool) (outStr string, err error) {
	if data == "" {
		err = errors.New("value can't be null")
		return
	}
	out, err := rec.operate([]byte(key), []byte(data), mode, true)
	if err != nil {
		return
	}
	return format.ResHandler(out, returnHex, false), nil
}
func (rec *sm4Crypto) Decrypt(key, data, mode string, isHex bool) (outStr string, err error) {
	if data == "" {
		return "", nil
	}
	var db []byte
	if isHex {
		db, err = hex.DecodeString(data)
		if err != nil {
			err = errors.New("hex decode failed")
			return
		}
	} else {
		db, err = base64.StdEncoding.DecodeString(data)
		if err != nil {
			err = errors.New("base64 decode failed")
			return
		}
	}
	out, err := rec.operate([]byte(key), db, mode, false)
	if err != nil {
		return
	}
	if out == nil {
		err = errors.New("decrypted failed")
		return
	}
	outStr = string(out)
	return
}
