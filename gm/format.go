package gm

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
)

func formatRet(d []byte, returnHex bool) (output string) {
	if returnHex {
		return strings.ToUpper(hex.EncodeToString(d))
	}
	return base64.StdEncoding.EncodeToString(d)
}
