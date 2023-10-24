package test

import (
	"fmt"
	"testing"

	"github.com/fainc/go-crypto/aes"
	"github.com/fainc/go-crypto/gm"
	"github.com/fainc/go-crypto/keypair"
	"github.com/fainc/go-crypto/md5"
	"github.com/fainc/go-crypto/rsa"
)

func TestMD5_Sum(t *testing.T) {
	fmt.Println(md5.Sum("123").ToHexString())
}

func TestAES_CBC(t *testing.T) {
	c := aes.NewCBC("1234567812345678")
	encrypt, err := c.Encrypt("123")
	if err != nil {
		panic(err)
	}
	fmt.Println(encrypt.ToBase64String())
	decrypted, err := c.DecryptWithFormat(encrypt.ToBase64String(), false)
	if err != nil {
		panic(err)
	}
	fmt.Println(decrypted)
}

func TestSM2_Encrypt(t *testing.T) {
	plainText := "test 123"
	keyPair, err := keypair.GenSM2KeyPair()
	if err != nil {
		panic(err)
	}
	pub := gm.NewSM2Public(keyPair.Public.ToHexString())
	pri := gm.NewSM2Private(keyPair.Private.ToHexString())
	encrypt, err := pub.Encrypt(plainText, 0)
	if err != nil {
		return
	}
	decrypted, err := pri.DecryptWithFormat(encrypt.ToHexString(), 0)
	if err != nil {
		return
	}
	fmt.Println("公钥", keyPair.Public.ToHexString())
	fmt.Println("私钥", keyPair.Private.ToHexString())
	fmt.Println("明文", plainText)
	fmt.Println("密文", encrypt.ToHexString())
	fmt.Println("解密", decrypted)
	fmt.Println("一致", decrypted == plainText)
}

func TestSM2_Sign(t *testing.T) {
	keyPair, err := keypair.GenSM2KeyPair()
	if err != nil {
		panic(err)
	}
	pub := gm.NewSM2Public(keyPair.Public.ToHexString())
	pri := gm.NewSM2Private(keyPair.Private.ToHexString())
	sign, err := pri.Sign("123")
	if err != nil {
		return
	}
	fmt.Println("公钥", keyPair.Public.ToHexString())
	fmt.Println("私钥", keyPair.Private.ToHexString())
	fmt.Println("签文", "123")
	fmt.Println("签名", sign.ToHexString())
	verify, err := pub.Verify("123", sign.ToHexString())
	if err != nil {
		panic(err)
	}
	fmt.Println("验签", verify)
}

func TestSM3_Sum(t *testing.T) {
	fmt.Println(gm.Sm3().Sum("123").ToHexString())
}
func TestSM4_Encrypt(t *testing.T) {
	c := gm.NewSm4("1234567812345678")
	encrypt, err := c.Encrypt("123ABCEFG00A", "ECB")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(encrypt.ToHexString())
	decrypted, err := c.DecryptWithFormat(encrypt.ToHexString(), "ECB")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println(decrypted)
}
func TestRSA_Encrypt(t *testing.T) {
	plainText := "test 123"
	key, err := keypair.GenRSAKeyPair(2048)
	if err != nil {
		fmt.Println(err)
		return
	}
	encrypt, err := rsa.NewPublic(key.Public.ToBase64String()).Encrypt(plainText)
	if err != nil {
		return
	}
	decrypted, err := rsa.NewPrivate(key.Private.ToBase64String()).DecryptWithFormat(encrypt.ToBase64String(), false)
	if err != nil {
		return
	}
	fmt.Println("公钥", key.Public.ToBase64String())
	fmt.Println("私钥", key.Private.ToBase64String())
	fmt.Println("明文", plainText)
	fmt.Println("密文", encrypt.ToBase64String())
	fmt.Println("解密", decrypted)
	fmt.Println("一致", decrypted == plainText)
}
