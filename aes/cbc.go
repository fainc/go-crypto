package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
)

type cbcCrypto struct {
}

func CBC() *cbcCrypto {
	return &cbcCrypto{}
}

// EncryptPKCS7 AES CBC
func (rec *cbcCrypto) EncryptPKCS7(key, text string, ivOption ...string) (string, error) {
	return rec.Encrypt(key, text, ivOption...)
}

func (rec *cbcCrypto) Encrypt(key, text string, ivOption ...string) (string, error) {
	if text == "" {
		return "", errors.New("empty data encrypt is unnecessary")
	}
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	blockSize := block.BlockSize()
	plainText := PKCS7Padding([]byte(text), blockSize)
	ivValue := ([]byte)(nil)
	if len(ivOption) > 0 {
		if len(ivOption[0]) != blockSize {
			return "", errors.New("IV length must equal block size")
		}
		ivValue = []byte(ivOption[0])
	} else {
		ivValue = []byte("0000000000000000")
	}
	blockMode := cipher.NewCBCEncrypter(block, ivValue)
	cipherText := make([]byte, len(plainText))
	blockMode.CryptBlocks(cipherText, plainText)
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func (rec *cbcCrypto) Decrypt(key, text string, ivOption ...string) (string, error) {
	cipherText, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	blockSize := block.BlockSize()
	if len(cipherText) < blockSize {
		return "", errors.New("cipherText too short")
	}
	ivValue := ([]byte)(nil)
	if len(ivOption) > 0 {
		if len(ivOption[0]) != blockSize {
			return "", errors.New("IV length must equal block size")
		}
		ivValue = []byte(ivOption[0])
	} else {
		ivValue = []byte("0000000000000000")
	}
	if len(cipherText)%blockSize != 0 {
		return "", errors.New("cipherText is not a multiple of the block size")
	}
	blockModel := cipher.NewCBCDecrypter(block, ivValue)
	plainText := make([]byte, len(cipherText))
	blockModel.CryptBlocks(plainText, cipherText)
	plainText, e := PKCS7UnPadding(plainText, blockSize)
	if e != nil {
		return "", e
	}
	if plainText == nil {
		return "", errors.New("decrypted failed")
	}
	return string(plainText), nil
}
func (rec *cbcCrypto) DecryptPKCS7(key, text string, ivOption ...string) (string, error) {
	return rec.Decrypt(key, text, ivOption...)
}
