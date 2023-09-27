package go_crypto

import (
	"fmt"
	"testing"

	"github.com/fainc/go-crypto/md5"
)

func TestMd5(_ *testing.T) {
	fmt.Println(md5.Encrypt("123", true))
	fmt.Println(md5.Encrypt("123", false))
}
