package aes

import (
	"bytes"
	"errors"
)

func PKCS7Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}
func PKCS5Padding(src []byte) []byte {
	return PKCS7Padding(src, 8)
}
func PKCS5UnPadding(src []byte, blockSize int) ([]byte, error) {
	return PKCS7UnPadding(src, blockSize)
}
func PKCS7UnPadding(src []byte, blockSize int) ([]byte, error) {
	length := len(src)
	if blockSize <= 0 {
		return nil, errors.New("invalid blocklen")
	}

	if length%blockSize != 0 || length == 0 {
		return nil, errors.New("invalid data len")
	}

	unpadding := int(src[length-1])
	if unpadding > blockSize || unpadding == 0 {
		return nil, errors.New("invalid pkcs padding")
	}

	padding := src[length-unpadding:]
	for i := 0; i < unpadding; i++ {
		if padding[i] != byte(unpadding) {
			return nil, errors.New("invalid pkcs padding")
		}
	}

	return src[:(length - unpadding)], nil
}
