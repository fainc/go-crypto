package test

import (
	"fmt"
	"testing"

	"github.com/fainc/go-crypto/aes"
)

func TestAES(t *testing.T) {
	pkcs7, err := aes.CBC().Encrypt("1234567812345678", "000000", "1000000000000000")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println(pkcs7)
	pkcs7d, err := aes.CBC().Decrypt("1234567812345678", pkcs7, "1000000000000001")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("data", pkcs7d)
}
