package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"github.com/fainc/go-crypto/format"
	"github.com/fainc/go-crypto/padding"
)

type cbcCrypto struct {
	block     cipher.Block
	defaultIV []byte
}

// NewCBC CBC模式加解密
func NewCBC(key string, defaultIV ...string) *cbcCrypto {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		panic(err.Error())
	}
	iv := make([]byte, block.BlockSize())
	if len(defaultIV) != 0 && defaultIV[0] != "" {
		iv = []byte(defaultIV[0])
	}
	return &cbcCrypto{block, iv}
}

// MustEncrypt Encrypt 的简化方法，不返回 err，出现错误时直接 panic
func (rec *cbcCrypto) MustEncrypt(plainText string, ivOption ...string) *format.RetFormatter {
	ret, err := rec.Encrypt(plainText, ivOption...)
	if err != nil {
		panic(err.Error())
	}
	return ret
}

// ivOption 使用自定义 IV 或默认 IV
func (rec *cbcCrypto) ivOption(iv ...string) []byte {
	if len(iv) != 0 && iv[0] != "" {
		return []byte(iv[0])
	}
	return rec.defaultIV
}

// Encrypt 加密 返回多种格式
func (rec *cbcCrypto) Encrypt(plainText string, ivOption ...string) (ret *format.RetFormatter, err error) {
	blockSize := rec.block.BlockSize()
	iv := rec.ivOption(ivOption...)
	if len(iv) != blockSize {
		return nil, errors.New("IV length must equal block size")
	}
	paddingText := padding.PKCS7Padding([]byte(plainText), blockSize)
	blockMode := cipher.NewCBCEncrypter(rec.block, iv)
	cipherText := make([]byte, len(paddingText))
	blockMode.CryptBlocks(cipherText, paddingText)
	return format.NewRet(cipherText), nil
}

// DecryptWithFormat 格式转换解密实用方法，支持常见的 hexString 和 base64 ，isHex 为 true 则转换 hexString ，为 false 则转换 base64
func (rec *cbcCrypto) DecryptWithFormat(cipherText string, isHex bool, ivOption ...string) (result string, err error) {
	var src []byte
	if isHex {
		src, err = hex.DecodeString(cipherText)
	} else {
		src, err = base64.StdEncoding.DecodeString(cipherText)
	}
	if err != nil {
		return
	}
	plainText, err := rec.Decrypt(src, rec.ivOption(ivOption...))
	if err != nil {
		return
	}
	return string(plainText), nil
}

// Decrypt 解密，密文是 base64 或 hexString 时需要提前 decode 数据，可以参考或使用 DecryptWithFormat 实用方法自动处理
func (rec *cbcCrypto) Decrypt(cipherText, iv []byte) (result []byte, err error) {
	blockSize := rec.block.BlockSize()
	if len(iv) != blockSize {
		return nil, errors.New("IV length must equal block size")
	}
	if len(cipherText) < blockSize {
		return nil, errors.New("cipherText too short")
	}
	if len(cipherText)%blockSize != 0 {
		return nil, errors.New("cipherText is not a multiple of the block size")
	}
	blockModel := cipher.NewCBCDecrypter(rec.block, iv)
	plainText := make([]byte, len(cipherText))
	blockModel.CryptBlocks(plainText, cipherText)
	plainText, err = padding.PKCS7UnPadding(plainText, blockSize)
	if err != nil {
		return nil, err
	}
	if plainText == nil {
		return nil, errors.New("decrypted failed")
	}
	return plainText, nil
}
