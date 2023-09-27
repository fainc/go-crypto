package gm

import (
	"errors"
	"os"

	"github.com/tjfoc/gmsm/sm3"
)

type sm3Crypto struct {
}

func Sm3() *sm3Crypto {
	return &sm3Crypto{}
}
func (rec *sm3Crypto) Sum(data string, returnHex bool, salt ...string) (output string) {
	h := sm3.New()
	str := data
	if len(salt) >= 1 {
		str += salt[0]
	}
	h.Write([]byte(str))
	sum := h.Sum(nil)
	return formatRet(sum, returnHex)
}

func (rec *sm3Crypto) SM3FileSum(filePath string, returnHex bool) (output string, err error) {
	f, err := os.ReadFile(filePath)
	if err != nil {
		err = errors.New("SM3FileSum 读取文件失败")
		return
	}
	h := sm3.New()
	h.Write(f)
	sum := h.Sum(nil)
	output = formatRet(sum, returnHex)
	return
}
