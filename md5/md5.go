package md5

import (
	"crypto/md5" //nolint:gosec

	"github.com/fainc/go-crypto/format"
)

func Encrypt(str string, toUpper bool) string {
	h := md5.New() //nolint:gosec
	h.Write([]byte(str))
	d := h.Sum(nil)
	return format.ResHandler(d, true, toUpper)
}
