package gm

import (
	"crypto/rand"
	"encoding/hex"
	"errors"

	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"

	"github.com/fainc/go-crypto/format"
)

type sm2Pub struct {
	public *sm2.PublicKey
}

type sm2Pri struct {
	private *sm2.PrivateKey
}

// NewSM2Public 公钥操作，加密、验签，密钥使用未经 der 编码的 hex
func NewSM2Public(publicHex string) *sm2Pub {
	pub, err := x509.ReadPublicKeyFromHex(publicHex)
	if err != nil {
		panic(err)
	}
	return &sm2Pub{pub}
}

// NewSM2Private 私钥操作，解密、加签，密钥使用未经 der 编码的 hex
func NewSM2Private(privateHex string) *sm2Pri {
	pri, err := x509.ReadPrivateKeyFromHex(privateHex)
	if err != nil {
		panic(err)
	}
	return &sm2Pri{pri}
}

// Encrypt mode 0 C1C3C2 mode1 C1C2C3 建议使用 mode 0，如无法解密可以尝试丢弃返回密文头部04标记
func (rec *sm2Pub) Encrypt(plainText string, mode int, asn1 ...bool) (cipherText *format.RetFormatter, err error) {
	if plainText == "" {
		err = errors.New("plain text can't be empty string")
		return nil, err
	}
	cipher, err := sm2.Encrypt(rec.public, []byte(plainText), rand.Reader, mode)
	if err != nil {
		return
	}
	if len(asn1) != 0 && asn1[0] { // 密文转ASN.1编码格式
		cipher, err = sm2.CipherMarshal(cipher)
		if err != nil {
			return
		}
	}
	return format.NewRet(cipher), nil
}

// DecryptWithFormat 格式转换解密实用方法，支持 hexString
func (rec *sm2Pri) DecryptWithFormat(cipherTextHex string, mode int, asn1 ...bool) (result string, err error) {
	cipherText, err := hex.DecodeString(cipherTextHex)
	if err != nil {
		return
	}
	plainText, err := rec.Decrypt(cipherText, mode, asn1...)
	if err != nil {
		return
	}
	return string(plainText), nil
}

// Decrypt mode 0 C1C3C2 mode1 C1C2C3
func (rec *sm2Pri) Decrypt(cipherText []byte, mode int, asn1 ...bool) (plainText []byte, err error) {
	if len(asn1) != 0 && asn1[0] { // 密文转ASN.1编码格式
		cipherText, err = sm2.CipherUnmarshal(cipherText)
		if err != nil {
			return
		}
	}
	plainText, err = sm2.Decrypt(rec.private, cipherText, mode)
	if err != nil || plainText == nil {
		err = errors.New("decrypted failed")
		return
	}
	return
}

// Sign 签名 der编解码 sm3杂凑
// 与其它语言或库互通时 需要仔细核对 sm3 杂凑、userId、asn.1 der编码是否各端一致
func (rec *sm2Pri) Sign(data string) (ret *format.RetFormatter, err error) {
	sign, err := rec.private.Sign(rand.Reader, []byte(data), nil) // sm2签名
	if err != nil {
		return nil, errors.New("signed failed")
	}
	return format.NewRet(sign), nil
}

// PublicVerify 签名验证 der编解码 sm3杂凑
// 注意，如前端使用 https://github.com/JuneAndGreen/sm-crypto/  der 和 hash 参数需要为true（启用杂凑和asn.1 der编码）
//  sm2.doSignature("123", privateHex,{der:true,hash:true})
// 与其它语言或库互通时 需要仔细核对 sm3 杂凑、userId、asn.1 der编码是否各端一致

func (rec *sm2Pub) Verify(data, signHex string) (ok bool, err error) {
	src, err := hex.DecodeString(signHex)
	if err != nil {
		err = errors.New("hex decode failed")
		return
	}
	ok = rec.public.Verify([]byte(data), src) // sm2验签
	return
}
