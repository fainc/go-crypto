package gm

import (
	"errors"
	"os"

	"github.com/tjfoc/gmsm/sm3"

	"github.com/fainc/go-crypto/format"
)

type sm3Crypto struct {
}

func Sm3() *sm3Crypto {
	return &sm3Crypto{}
}
func (rec *sm3Crypto) Sum(data string, returnHex, hex2Upper bool) (output string) {
	h := sm3.New()
	str := data
	h.Write([]byte(str))
	sum := h.Sum(nil)
	return format.ResHandler(sum, returnHex, hex2Upper)
}

func (rec *sm3Crypto) SumFile(filePath string, returnHex, hex2Upper bool) (output string, err error) {
	f, err := os.ReadFile(filePath)
	if err != nil {
		err = errors.New("SM3SumFile path error")
		return
	}
	h := sm3.New()
	h.Write(f)
	sum := h.Sum(nil)
	output = format.ResHandler(sum, returnHex, hex2Upper)
	return
}
