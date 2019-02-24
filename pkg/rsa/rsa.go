package rsa

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
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

// ReadPEM looks for an RSA private key into a PEM certificate
func ReadPEM(b []byte) (*rsa.PrivateKey, error) {

	der, _ := pem.Decode(b)
	if der == nil {
		return nil, errors.New("private key file doesn't contain a PEM encoded key")
	}

	key, err := x509.ParsePKCS1PrivateKey(der.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cannot parse signing key file: %s", err.Error())
	}

	return key, nil
}
