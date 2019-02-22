package rsa

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// GenerateKey using the informed size
func GenerateKey(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

// WritePEM serializes the RSA key into PEM format
func WritePEM(key *rsa.PrivateKey) (string, error) {
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
