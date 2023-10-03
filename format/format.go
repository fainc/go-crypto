package format

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"strings"
)

// ResHandler 结果返回处理，返回hex或者base64
func ResHandler(d []byte, returnHex, hexToUpper bool) (output string) {
	if returnHex {
		h := hex.EncodeToString(d)
		if !hexToUpper {
			return h
		}
		return strings.ToUpper(h)
	}
	return base64.StdEncoding.EncodeToString(d)
}

// PemFormat 格式化PEM t = RSA PUBLIC KEY \ RSA PRIVATE KEY \ ...
func PemFormat(b []byte, t string) (priPem string) {
	pri := pem.EncodeToMemory(&pem.Block{
		Type:  t,
		Bytes: b,
	})
	return string(pri)
}
