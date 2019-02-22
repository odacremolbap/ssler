package cert

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// GenerateRSAKey using the informed size
func GenerateRSAKey(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

// RSAtoPEM serializes the RSA key into PEM format
func RSAtoPEM(key *rsa.PrivateKey) (string, error) {
	var b bytes.Buffer
	err := pem.Encode(
		&b,
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		})
	if err != nil {
		return "", fmt.Errorf("error PEM encoding RSA key: %s", err.Error())
	}

	return b.String(), nil
}
