package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
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
	Serial      *big.Int
	NotBefore   time.Time
	NotAfter    time.Time
	DNSNames    []string
	IPAddresses []string
	IsCA        bool
	KeyUsage    x509.KeyUsage
	ExtKeyUsage x509.ExtKeyUsage
}

// Manager manages certificates
type Manager struct {
}

func (c *Manager) GenRSAKey(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

func (c *Manager) GenX509(key *rsa.PrivateKey) {
	// x509cert := x509.Certificate{}
	x := x509.Certificate{}
	x.KeyUsage
}

func genSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, (&big.Int{}).Exp(big.NewInt(2), big.NewInt(159), nil))
}
