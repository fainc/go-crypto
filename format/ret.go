package format

import (
	"encoding/base64"
	"encoding/hex"
)

type RetFormatter struct {
	d []byte
}

func NewRet(d []byte) *RetFormatter {
	return &RetFormatter{d}
}

func (rec *RetFormatter) ToBase64String() string {
	return base64.StdEncoding.EncodeToString(rec.d)
}

func (rec *RetFormatter) ToHexString() string {
	return hex.EncodeToString(rec.d)
}

// ToString 简化方法，一般用于配置化场景，toHex 为 true 返回 hex ，否则返回 base64
func (rec *RetFormatter) ToString(toHex bool) string {
	if toHex {
		return rec.ToHexString()
	}
	return rec.ToBase64String()
}

func (rec *RetFormatter) Bytes() []byte {
	return rec.d
}
