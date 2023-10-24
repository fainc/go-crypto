package keypair

import (
	"crypto/rand"
	"errors"

	"github.com/tjfoc/gmsm/sm2"

	"github.com/fainc/go-crypto/format"
)

// GenSM2KeyPair 生成 SM2 密钥对（未经der编码的裸密钥，建议hex存储）
func GenSM2KeyPair() (keyPair KeyPair, err error) {
	keyPair = KeyPair{}
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return
	}
	if !key.Curve.IsOnCurve(key.X, key.Y) {
		err = errors.New("key is not on curve")
		return
	}
	keyPair.Private = format.NewRet(key.D.Bytes())                                                   // 裸私钥
	keyPair.Public = format.NewRet(append([]byte{0x04}, append(key.X.Bytes(), key.Y.Bytes()...)...)) // 裸公钥
	return
}
