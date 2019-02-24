package cert

import (
	"bytes"
	"encoding/pem"
	"fmt"
)

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
