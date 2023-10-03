package gm

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"

	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"

	"github.com/fainc/go-crypto/format"
)

type sm2Crypto struct {
}

func Sm2() *sm2Crypto {
	return &sm2Crypto{}
}
func (rec *sm2Crypto) sm2generateKey() (key *sm2.PrivateKey, err error) {
	key, err = sm2.GenerateKey(rand.Reader)
	if err != nil {
		return
	}
	if !key.Curve.IsOnCurve(key.X, key.Y) {
		err = errors.New("key is not on curve")
		return
	}
	return
}

// GenerateKey 生成国密 SM2 密钥
func (rec *sm2Crypto) GenerateKey(pwd string) (pri, pub, priHex, pubHex string, err error) {
	var password []byte
	if pwd != "" {
		password = []byte(pwd)
	}
	key, err := rec.sm2generateKey()
	if err != nil {
		return
	}
	priByte, err := x509.WritePrivateKeyToPem(key, password) // 生成密钥文件
	if err != nil {
		return
	}
	pubKey, _ := key.Public().(*sm2.PublicKey)
	pubByte, err := x509.WritePublicKeyToPem(pubKey) // 生成公钥文件
	if err != nil {
		return
	}
	pri = string(priByte)
	pub = string(pubByte)

	// 解决前后端对接问题，hex密钥输出给JS端使用
	// 前后端对接注意JS 是否需要要给公钥和密文处理04标识
	// https://github.com/JuneAndGreen/sm-crypto/issues/42

	// 私钥 hex
	priHex = hex.EncodeToString(key.D.Bytes())
	// 公钥 hex（如需移除04软件标识请自行处理）
	pubHex = "04" + hex.EncodeToString(pubKey.X.Bytes()) + hex.EncodeToString(pubKey.Y.Bytes())
	return
}

func (rec *sm2Crypto) ReadPrivateKeyFromPem(priPem, password string) (pri *sm2.PrivateKey, err error) {
	pri, err = x509.ReadPrivateKeyFromPem([]byte(priPem), []byte(password))
	if err != nil {
		err = errors.New("read private key from pem failed")
		return
	}
	return
}
func (rec *sm2Crypto) ReadPrivateKeyFromPath(filePath, password string) (pri *sm2.PrivateKey, err error) {
	f, err := os.ReadFile(filePath)
	if err != nil {
		err = errors.New("read private key from path failed")
		return
	}
	pri, err = x509.ReadPrivateKeyFromPem(f, []byte(password))
	if err != nil {
		err = errors.New("read private key from pem failed")
		return
	}
	return
}

func (rec *sm2Crypto) ReadPublicKeyFromPem(pubPem string) (pub *sm2.PublicKey, err error) {
	pub, err = x509.ReadPublicKeyFromPem([]byte(pubPem))
	if err != nil {
		err = errors.New("read public key from pem failed")
		return
	}
	return
}

func (rec *sm2Crypto) ReadPublicKeyFromPath(filePath string) (pub *sm2.PublicKey, err error) {
	f, err := os.ReadFile(filePath)
	if err != nil {
		err = errors.New("read public key from path failed")
		return
	}
	pub, err = x509.ReadPublicKeyFromPem(f)
	if err != nil {
		err = errors.New("read public key from pem failed")
		return
	}
	return
}
func (rec *sm2Crypto) EncryptAsn1(pubPem, data string, returnHex bool) (cipherText string, err error) {
	if data == "" {
		err = errors.New("data can not be null")
		return
	}
	pub, err := x509.ReadPublicKeyFromPem([]byte(pubPem))
	if err != nil {
		return
	}
	cipher, err := pub.EncryptAsn1([]byte(data), rand.Reader) // sm2加密
	if err != nil {
		return
	}
	return format.ResHandler(cipher, returnHex, false), nil
}

// Encrypt mode 0 C1C3C2 mode1 C1C2C3
func (rec *sm2Crypto) Encrypt(pubPem, data string, mode int, returnHex bool) (cipherText string, err error) {
	if data == "" {
		err = errors.New("data can not be null")
		return
	}
	pub, err := x509.ReadPublicKeyFromPem([]byte(pubPem))
	if err != nil {
		return
	}
	cipher, err := sm2.Encrypt(pub, []byte(data), rand.Reader, mode)
	if err != nil {
		return
	}
	return format.ResHandler(cipher, returnHex, false), nil
}
func (rec *sm2Crypto) DecryptAsn1(priPem, pwd, data string, isHex bool) (plainText string, err error) {
	if data == "" {
		return
	}
	var password []byte
	if pwd != "" {
		password = []byte(pwd)
	}
	pri, err := x509.ReadPrivateKeyFromPem([]byte(priPem), password)
	if err != nil {
		err = errors.New("read private key from pem failed")
		return
	}
	var d []byte
	if isHex {
		d, err = hex.DecodeString(data)
		if err != nil {
			err = errors.New("hex decode failed")
			return
		}
	} else {
		d, err = base64.StdEncoding.DecodeString(data)
		if err != nil {
			err = errors.New("base64 decode failed")
			return
		}
	}

	plain, err := pri.DecryptAsn1(d) // sm2解密
	if err != nil || plain == nil {
		err = errors.New("decrypted failed")
		return
	}
	return string(plain), nil
}

// Decrypt mode 0 C1C3C2 mode1 C1C2C3
func (rec *sm2Crypto) Decrypt(priPem, pwd, data string, mode int, isHex bool) (plainText string, err error) {
	if data == "" {
		return
	}
	var password []byte
	if pwd != "" {
		password = []byte(pwd)
	}
	pri, err := x509.ReadPrivateKeyFromPem([]byte(priPem), password)
	if err != nil {
		err = errors.New("read private key from pem failed")
		return
	}
	var d []byte
	if isHex {
		d, err = hex.DecodeString(data)
		if err != nil {
			err = errors.New("hex decode failed")
			return
		}
	} else {
		d, err = base64.StdEncoding.DecodeString(data)
		if err != nil {
			err = errors.New("base64 decode failed")
			return
		}
	}
	plain, err := sm2.Decrypt(pri, d, mode)
	if err != nil || plain == nil {
		err = errors.New("decrypted failed")
		return
	}
	return string(plain), nil
}

// PrivateSign 签名 der编解码 sm3杂凑
// 与其它语言或库互通时 需要仔细核对 sm3 杂凑、userId、asn.1 der编码是否各端一致
func (rec *sm2Crypto) PrivateSign(priPem, pwd, data string, returnHex bool) (signStr string, err error) {
	if data == "" {
		err = errors.New("data can not be null")
		return
	}
	var password []byte
	if pwd != "" {
		password = []byte(pwd)
	}
	pri, err := x509.ReadPrivateKeyFromPem([]byte(priPem), password)
	if err != nil {
		err = errors.New("read private key from pem failed")
		return
	}
	sign, err := pri.Sign(rand.Reader, []byte(data), nil) // sm2签名
	if err != nil {
		err = errors.New("signed failed")
		return
	}
	return format.ResHandler(sign, returnHex, false), nil
}

// PublicVerify 签名验证 der编解码 sm3杂凑
// 注意，如前端使用 https://github.com/JuneAndGreen/sm-crypto/  der 和 hash 参数需要为true（启用杂凑和asn.1 der编码）
//  sm2.doSignature("123", privateHex,{der:true,hash:true})
// 与其它语言或库互通时 需要仔细核对 sm3 杂凑、userId、asn.1 der编码是否各端一致

func (rec *sm2Crypto) PublicVerify(pubPem, data, sign string, isHex bool) (ok bool, err error) {
	if data == "" {
		err = errors.New("data can not be null")
		return
	}
	pub, err := x509.ReadPublicKeyFromPem([]byte(pubPem))
	if err != nil {
		err = errors.New("read public key from pem failed")
		return
	}
	var sd []byte
	if isHex {
		sd, err = hex.DecodeString(sign)
		if err != nil {
			err = errors.New("hex decode failed")
			return
		}
	} else {
		sd, err = base64.StdEncoding.DecodeString(sign)
		if err != nil {
			err = errors.New("base 64 decode failed")
			return
		}
	}
	ok = pub.Verify([]byte(data), sd) // sm2验签
	return
}
