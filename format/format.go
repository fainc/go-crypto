package format

import (
	"encoding/pem"
)

// PemFormat 格式化PEM t = RSA PUBLIC KEY \ RSA PRIVATE KEY \ ...
func PemFormat(b []byte, t string) (priPem string) {
	pri := pem.EncodeToMemory(&pem.Block{
		Type:  t,
		Bytes: b,
	})
	return string(pri)
}
