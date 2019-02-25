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
		{testName: "t1",
			keySize: 4096,
		},
		{testName: "t2",
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
