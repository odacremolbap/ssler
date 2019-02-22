package cert

import (
	"crypto/rand"
	"math/big"
)

// Manager manages certificates
type Manager struct {
}

// func (c *Manager) GenX509(key *rsa.PrivateKey) {
// 	// x509cert := x509.Certificate{}
// 	// x := x509.Certificate{}
// 	// x.KeyUsage
// }

func genSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, (&big.Int{}).Exp(big.NewInt(2), big.NewInt(159), nil))
}
