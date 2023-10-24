package keypair

import (
	"github.com/fainc/go-crypto/format"
)

type KeyPair struct {
	Public  *format.RetFormatter
	Private *format.RetFormatter
}
