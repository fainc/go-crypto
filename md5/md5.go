package md5

import (
	"crypto/md5" //nolint:gosec

	"github.com/fainc/go-crypto/format"
)

func Sum(str string) *format.RetFormatter {
	h := md5.New() //nolint:gosec
	h.Write([]byte(str))
	sum := h.Sum(nil)
	return format.NewRet(sum)
}
