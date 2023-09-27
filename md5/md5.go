package md5

import (
	"crypto/md5" //nolint:gosec
	"encoding/hex"
	"strings"
)

func Encrypt(str string, toUpper bool) string {
	h := md5.New() //nolint:gosec
	h.Write([]byte(str))
	if toUpper {
		return strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
	}
	return hex.EncodeToString(h.Sum(nil))
}
