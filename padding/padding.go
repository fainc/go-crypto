package padding

import (
	"bytes"
	"errors"
)

// PKCS7Padding PKCS7 数据填充
func PKCS7Padding(src []byte, blockSize int) []byte {
	pad := blockSize - len(src)%blockSize
	padText := bytes.Repeat([]byte{byte(pad)}, pad)
	return append(src, padText...)
}

// PKCS7UnPadding 数据去填充，并验证数据填充是否规范
func PKCS7UnPadding(src []byte, blockSize int) ([]byte, error) {
	length := len(src)
	if blockSize <= 0 {
		return nil, errors.New("invalid block size")
	}
	// 对数据进行blockSize验证
	if length%blockSize != 0 || length == 0 {
		return nil, errors.New("invalid data len")
	}

	// 验证数据最后一位填充标记是否正确，解决错误数据去填充报错问题，并一定程度上验证了解密后数据是否正确（符合填充规范不一定正确，反之一定错误）
	unPadding := int(src[length-1])
	if unPadding > blockSize || unPadding == 0 {
		return nil, errors.New("invalid padding")
	}

	padding := src[length-unPadding:]
	for i := 0; i < unPadding; i++ {
		if padding[i] != byte(unPadding) { // 对每位填充数据进行验证，一定程度上验证了解密后数据是否正确（符合填充规范不一定正确，反之一定错误）
			return nil, errors.New("pad block corrupted")
		}
	}
	return src[:(length - unPadding)], nil
}

// PKCS5Padding PKCS5 是 PKCS7 的子集。
// 跨语言或跨系统对接请注意，对方可能没有正确声明规范，PKCS7 完全兼容 PKCS5，优先使用 PKCS7。
// 目前主流的对称加密算法的 blockSize 是 16，如 AES 与 SM4，应当为PKCS7。
func PKCS5Padding(src []byte) []byte {
	return PKCS7Padding(src, 8)
}

// PKCS5UnPadding  PKCS5 是 PKCS7 的子集。
// 跨语言或跨系统对接请注意，对方可能没有正确声明规范，PKCS7 完全兼容 PKCS5，优先使用 PKCS7。
// 目前主流的对称加密算法的 blockSize 是 16，如 AES 与 SM4，应当为PKCS7。
func PKCS5UnPadding(src []byte) ([]byte, error) {
	return PKCS7UnPadding(src, 8)
}
