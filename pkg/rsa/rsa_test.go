package rsa

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateKey(t *testing.T) {
	var testData = []struct {
		testName string
		keySize  int
	}{
		{testName: "t4096",
			keySize: 4096,
		},
		{testName: "t1024",
			keySize: 1024,
		},
	}
	for _, td := range testData {
		key, _ := GenerateKey(td.keySize)
		err := key.Validate()
		assert.Nil(t, err, "test: %s", td.testName)
		assert.Equalf(t, td.keySize, key.N.BitLen(), "test: %s", td.testName)
	}
}

func TestPEMEncode(t *testing.T) {
	var testData = []struct {
		testName string
		keySize  int
	}{
		{testName: "t4096",
			keySize: 4096,
		},
		{testName: "t1024",
			keySize: 1024,
		},
	}
	for _, td := range testData {
		key, _ := GenerateKey(td.keySize)
		pem, err := WritePEM(key)
		assert.Nil(t, err, "test writePEM: %s", td.testName)
		retKey, err := ReadPEM([]byte(pem))
		assert.Nil(t, err, "test readPEM: %s", td.testName)
		assert.Equalf(t, key, retKey, "test: %s", td.testName)
	}
}
