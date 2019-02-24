package cert

import (
	"crypto/x509"
	"testing"

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
