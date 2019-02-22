package cert

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStringArrayToKeyUsage(t *testing.T) {

	var testData = []struct {
		testName    string
		keyUsage    []string
		keyUsageRet x509.KeyUsage
		errorRet    bool
	}{
		{
			testName:    "empty usage",
			keyUsage:    []string{},
			keyUsageRet: 0,
			errorRet:    false,
		},
		{
			testName:    "one usage",
			keyUsage:    []string{"KeyUsageDigitalSignature"},
			keyUsageRet: x509.KeyUsageDigitalSignature,
			errorRet:    false,
		},
		{
			testName: "multi usage",
			keyUsage: []string{"KeyUsageKeyEncipherment",
				"KeyUsageDigitalSignature",
				"KeyUsageCertSign"},
			keyUsageRet: x509.KeyUsageKeyEncipherment |
				x509.KeyUsageDigitalSignature |
				x509.KeyUsageCertSign,
			errorRet: false,
		},
		{
			testName: "error usage",
			keyUsage: []string{"KeyUsageKeyEncipherment",
				"KeyUsageDigitalSignature",
				"WRONG"},
			keyUsageRet: 0,
			errorRet:    true,
		},
	}

	for _, td := range testData {
		k, err := StringArrayToKeyUsage(td.keyUsage)

		if td.errorRet {
			assert.Errorf(t, err, "test: %s", td.testName)
		} else {
			assert.NoErrorf(t, err, "test: %s", td.testName)
		}
		assert.Equal(t, td.keyUsageRet, k, "test: %s", td.testName)
	}
}
