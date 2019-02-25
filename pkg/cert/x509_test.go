package cert

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/odacremolbap/xfon/pkg/rsa"

	"github.com/stretchr/testify/assert"
)

func TestStringToKeyUsage(t *testing.T) {

	var testData = []struct {
		testName    string
		keyUsage    string
		keyUsageRet x509.KeyUsage
		errorRet    bool
	}{
		{
			testName:    "empty usage",
			keyUsage:    "",
			keyUsageRet: 0,
			errorRet:    false,
		},
		{
			testName:    "one usage",
			keyUsage:    "KeyUsageDigitalSignature",
			keyUsageRet: x509.KeyUsageDigitalSignature,
			errorRet:    false,
		},
		{
			testName: "multi usage",
			keyUsage: "KeyUsageKeyEncipherment,KeyUsageDigitalSignature,KeyUsageCertSign",
			keyUsageRet: x509.KeyUsageKeyEncipherment |
				x509.KeyUsageDigitalSignature |
				x509.KeyUsageCertSign,
			errorRet: false,
		},
		{
			testName:    "error usage",
			keyUsage:    "KeyUsageKeyEncipherment,KeyUsageDigitalSignature,WRONG",
			keyUsageRet: 0,
			errorRet:    true,
		},
	}

	for _, td := range testData {
		k, err := StringToKeyUsage(td.keyUsage)

		if td.errorRet {
			assert.Errorf(t, err, "test: %s", td.testName)
		} else {
			assert.NoErrorf(t, err, "test: %s", td.testName)
		}
		assert.Equal(t, td.keyUsageRet, k, "test: %s", td.testName)
	}
}

func TestStringToExtKeyUsage(t *testing.T) {

	var testData = []struct {
		testName       string
		extKeyUsage    string
		extKeyUsageRet []x509.ExtKeyUsage
		errorRet       bool
	}{
		{
			testName:       "empty usage",
			extKeyUsage:    "",
			extKeyUsageRet: []x509.ExtKeyUsage(nil),
			errorRet:       false,
		},
		{
			testName:       "one usage",
			extKeyUsage:    "ExtKeyUsageServerAuth",
			extKeyUsageRet: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			errorRet:       false,
		},
		{
			testName:       "multi usage",
			extKeyUsage:    "ExtKeyUsageServerAuth,ExtKeyUsageClientAuth",
			extKeyUsageRet: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			errorRet:       false,
		},
		{
			testName:       "error usage",
			extKeyUsage:    "ExtKeyUsageServerAuth,WRONG",
			extKeyUsageRet: []x509.ExtKeyUsage(nil),
			errorRet:       true,
		},
	}

	for _, td := range testData {
		k, err := StringToExtKeyUsage(td.extKeyUsage)

		if td.errorRet {
			assert.Errorf(t, err, "test: %s", td.testName)
		} else {
			assert.NoErrorf(t, err, "test: %s", td.testName)
		}
		assert.Equal(t, td.extKeyUsageRet, k, "test: %s", td.testName)
	}
}

func TestX509Generation(t *testing.T) {

	var testData = []struct {
		testName string
		keySize  int
		x509     *X509Simplified
	}{
		{
			testName: "simple1",
			keySize:  4096,
			x509: &X509Simplified{
				Subject: &Subject{
					CommonName: "simple1",
				},
				NotBefore: time.Now().UTC(),
				NotAfter:  time.Now().AddDate(0, 0, 100).UTC(),
				IsCA:      true,
			},
		},
		{
			testName: "simple2",
			keySize:  4096,
			x509: &X509Simplified{
				Subject: &Subject{
					CommonName:   "simple2",
					Organization: "organization2",
				},
				NotBefore: time.Now().UTC(),
				NotAfter:  time.Now().AddDate(0, 0, 100).UTC(),
				IsCA:      true,
			},
		},
	}

	for _, td := range testData {
		key, _ := rsa.GenerateKey(td.keySize)
		b, err := GenerateX509SelfSignedCertificate(td.x509, key)

		c, err := x509.ParseCertificate(b)
		assert.Nil(t, err)
		assert.Equal(t, td.x509.Subject.CommonName, c.Subject.CommonName)
		if td.x509.Subject.Organization != "" {
			assert.Equal(t, td.x509.Subject.Organization, c.Subject.Organization[0])
		}
		if td.x509.Subject.OrganizationalUnit != "" {
			assert.Equal(t, td.x509.Subject.OrganizationalUnit, c.Subject.OrganizationalUnit[0])
		}

		assert.Equal(t, td.x509.IsCA, c.IsCA)
	}

}
