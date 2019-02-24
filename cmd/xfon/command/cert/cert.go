package cert

import (
	"crypto/x509"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/odacremolbap/xfon/pkg/cert"
	"github.com/odacremolbap/xfon/pkg/filesystem"
	"github.com/odacremolbap/xfon/pkg/rsa"
	"github.com/spf13/cobra"
)

var (
	// simplified subject fields
	commonName         string
	organization       string
	organizationalUnit string

	// features
	validityDays int
	isCA         bool
	keyUsages    string
	extKeyUsages string
	usage        x509.KeyUsage
	extUsage     []x509.ExtKeyUsage

	// in and out
	keyIn   string
	certOut string

	// RootCmd contains certificate management commands
	RootCmd = &cobra.Command{
		Use:   "x509",
		Short: "x509 manages certificates",
		Run:   runHelp,
	}

	// NewCmd creates certificate key pair
	NewCmd = &cobra.Command{
		Use:   "new",
		Short: "creates certificate key pair",
		Run:   newFunc,
		Args:  newFuncVal,
	}

	// SignCmd manages private keys
	SignCmd = &cobra.Command{
		Use:   "signed",
		Short: "creates a signed certificate pair",
		Run:   runHelp,
	}
)

func runHelp(cmd *cobra.Command, args []string) {
	cmd.Help()
}

func init() {

	// subject
	NewCmd.Flags().StringVar(&commonName, "common-name", "", "CN for certificate")
	NewCmd.Flags().StringVar(&organization, "organization", "", "O for certificate")
	NewCmd.Flags().StringVar(&organizationalUnit, "organizational-unit", "", "OU for certificate")

	// features
	NewCmd.Flags().IntVar(&validityDays, "days", 0, "number of validity days for the generated certificate")
	NewCmd.MarkFlagRequired("days")
	NewCmd.Flags().BoolVar(&isCA, "ca", false, "[true|false] wether the certificate is a CA")
	NewCmd.Flags().StringVar(&keyUsages, "usages", "", "comma separated key usages for the certificate")
	NewCmd.Flags().StringVar(&extKeyUsages, "ex-usages", "", "comma separated extended key usages for the certificate")

	// in and out
	NewCmd.Flags().StringVar(&keyIn, "key-in", "", "path to key used for signing")
	NewCmd.MarkFlagRequired("key-in")
	NewCmd.Flags().StringVar(&certOut, "cert-out", "", "generated certificate file path")
	NewCmd.MarkFlagRequired("cert-out")

	RootCmd.AddCommand(NewCmd)
	RootCmd.AddCommand(SignCmd)
}

func newFuncVal(cmd *cobra.Command, args []string) error {

	var err error
	usage, err = cert.StringToKeyUsage(keyUsages)
	if err != nil {
		return fmt.Errorf("error parsing key usage: %+v", err)
	}

	extUsage, err = cert.StringToExtKeyUsage(extKeyUsages)
	if err != nil {
		return fmt.Errorf("error parsing extended key usage: %+v", err)
	}

	return nil
}

// newFunc runs the new RSA command
func newFunc(cmd *cobra.Command, args []string) {
	ki, err := filesystem.ReadContentsFromFile(keyIn)
	if err != nil {
		log.Printf("error reading key: %v", err.Error())
		os.Exit(-1)
	}

	key, err := rsa.ReadPEM(ki)
	if err != nil {
		log.Printf("no key found at %q: %v", keyIn, err.Error())
		os.Exit(-1)
	}

	tb := time.Now().UTC()
	ta := tb.AddDate(0, 0, validityDays).UTC()

	x := &cert.X509{
		Subject: &cert.Subject{
			CommonName:         commonName,
			Organization:       organization,
			OrganizationalUnit: organizationalUnit,
		},
		Serial:      new(big.Int).SetInt64(0),
		NotBefore:   tb,
		NotAfter:    ta,
		IsCA:        isCA,
		KeyUsage:    usage,
		ExtKeyUsage: extUsage,
	}

	b, err := cert.GenerateX509SelfSignedCertificate(x, key)
	if err != nil {
		log.Printf("error generating certificate: %v", err.Error())
		os.Exit(-1)
	}

	pem, err := cert.WritePEM(b)
	if err != nil {
		log.Printf("error encoding certificate: %v", err.Error())
		os.Exit(-1)
	}

	filesystem.WriteContentsToFile(certOut, pem)
}
