package gm

import (
	"github.com/tjfoc/gmsm/sm3"

	"github.com/fainc/go-crypto/format"
)

type sm3Crypto struct {
}

func Sm3() *sm3Crypto {
	return &sm3Crypto{}
}
func (rec *sm3Crypto) Sum(data string) (output *format.RetFormatter) {
	h := sm3.New()
	str := data
	h.Write([]byte(str))
	sum := h.Sum(nil)
	return format.NewRet(sum)
}
