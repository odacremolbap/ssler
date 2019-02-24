package cert

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

var (
	// KeyUsageChoices is a set of string choices that map to the
	// X509 key usage representation
	KeyUsageChoices map[string]x509.KeyUsage

	// ExtKeyUsageChoices is a set of string choices that map to the
	// X509 extended key usage representation
	ExtKeyUsageChoices map[string]x509.ExtKeyUsage
)

func init() {
	KeyUsageChoices = map[string]x509.KeyUsage{
		"KeyUsageDigitalSignature":  x509.KeyUsageDigitalSignature,
		"KeyUsageContentCommitment": x509.KeyUsageContentCommitment,
		"KeyUsageKeyEncipherment":   x509.KeyUsageKeyEncipherment,
		"KeyUsageDataEncipherment":  x509.KeyUsageDataEncipherment,
		"KeyUsageKeyAgreement":      x509.KeyUsageKeyAgreement,
		"KeyUsageCertSign":          x509.KeyUsageCertSign,
		"KeyUsageCRLSign":           x509.KeyUsageCRLSign,
		"KeyUsageEncipherOnly":      x509.KeyUsageEncipherOnly,
		"KeyUsageDecipherOnly":      x509.KeyUsageDecipherOnly,
	}

	ExtKeyUsageChoices = map[string]x509.ExtKeyUsage{
		"ExtKeyUsageAny":                            x509.ExtKeyUsageAny,
		"ExtKeyUsageServerAuth":                     x509.ExtKeyUsageServerAuth,
		"ExtKeyUsageClientAuth":                     x509.ExtKeyUsageClientAuth,
		"ExtKeyUsageCodeSigning":                    x509.ExtKeyUsageCodeSigning,
		"ExtKeyUsageEmailProtection":                x509.ExtKeyUsageEmailProtection,
		"ExtKeyUsageIPSECEndSystem":                 x509.ExtKeyUsageIPSECEndSystem,
		"ExtKeyUsageIPSECTunnel":                    x509.ExtKeyUsageIPSECTunnel,
		"ExtKeyUsageIPSECUser":                      x509.ExtKeyUsageIPSECUser,
		"ExtKeyUsageTimeStamping":                   x509.ExtKeyUsageTimeStamping,
		"ExtKeyUsageOCSPSigning":                    x509.ExtKeyUsageOCSPSigning,
		"ExtKeyUsageMicrosoftServerGatedCrypto":     x509.ExtKeyUsageMicrosoftServerGatedCrypto,
		"ExtKeyUsageNetscapeServerGatedCrypto":      x509.ExtKeyUsageNetscapeServerGatedCrypto,
		"ExtKeyUsageMicrosoftCommercialCodeSigning": x509.ExtKeyUsageMicrosoftCommercialCodeSigning,
		"ExtKeyUsageMicrosoftKernelCodeSigning":     x509.ExtKeyUsageMicrosoftKernelCodeSigning,
	}
}

// X509 simplified
type X509 struct {
	Subject     *Subject
	Serial      *big.Int
	NotBefore   time.Time
	NotAfter    time.Time
	DNSNames    []string
	IPAddresses []net.IP
	IsCA        bool
	KeyUsage    x509.KeyUsage
	ExtKeyUsage []x509.ExtKeyUsage
}

// Subject for x509 certificate
type Subject struct {
	CommonName         string
	Organization       string
	OrganizationalUnit string
}

// StringToKeyUsage converts a string array into a key usage type
func StringToKeyUsage(keyUsage string) (x509.KeyUsage, error) {
	var u x509.KeyUsage
	ku := strings.Split(keyUsage, ",")
	for _, key := range ku {
		if key == "" {
			continue
		}
		if v, ok := KeyUsageChoices[key]; ok {
			u = u | v
		} else {
			return 0, fmt.Errorf("unknown key usage: %s", key)
		}
	}
	return u, nil
}

// StringToExtKeyUsage converts a string array into an extended key usage type
func StringToExtKeyUsage(extKeyUsage string) ([]x509.ExtKeyUsage, error) {
	var u []x509.ExtKeyUsage
	ke := strings.Split(extKeyUsage, ",")
	for _, key := range ke {
		if key == "" {
			continue
		}
		if v, ok := ExtKeyUsageChoices[key]; ok {
			u = append(u, v)
		} else {
			return nil, fmt.Errorf("unknown extended key usage: %s", key)
		}
	}
	return u, nil
}

// GenerateX509SelfSignedCertificate takes a simplified x509 definition and an RSA key,
// and generates a certificate
func GenerateX509SelfSignedCertificate(c *X509, key *rsa.PrivateKey) ([]byte, error) {
	if c.Serial == nil {
		c.Serial = new(big.Int).SetInt64(0)
	}
	return GenerateX509Certificate(c, nil, key, key)
}

// GenerateX509Certificate using the passed parameters
func GenerateX509Certificate(c *X509, parent *x509.Certificate, publicKey *rsa.PrivateKey, signingKey *rsa.PrivateKey) ([]byte, error) {

	subject := pkix.Name{
		CommonName: c.Subject.CommonName,
	}
	if c.Subject.Organization != "" {
		subject.Organization = []string{c.Subject.Organization}
	}
	if c.Subject.OrganizationalUnit != "" {
		subject.OrganizationalUnit = []string{c.Subject.OrganizationalUnit}
	}

	x509cert := &x509.Certificate{
		Subject:               subject,
		SerialNumber:          c.Serial,
		DNSNames:              c.DNSNames,
		IPAddresses:           c.IPAddresses,
		NotBefore:             c.NotBefore,
		NotAfter:              c.NotAfter,
		BasicConstraintsValid: c.IsCA,
		IsCA:                  c.IsCA,
		KeyUsage:              c.KeyUsage,
		ExtKeyUsage:           c.ExtKeyUsage,
	}
	if parent == nil {
		parent = x509cert
	}

	b, err := x509.CreateCertificate(
		rand.Reader,
		x509cert,
		parent,
		&publicKey.PublicKey,
		signingKey)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// WritePEM serializes the certificate into a PEM string
func WritePEM(cert []byte) (string, error) {

	var p bytes.Buffer
	err := pem.Encode(
		&p,
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert,
		})
	if err != nil {
		return "", fmt.Errorf("error PEM encoding certificate: %s", err.Error())
	}

	return p.String(), nil
}
