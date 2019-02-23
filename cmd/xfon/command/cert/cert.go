package cert

import (
	"crypto/x509"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/odacremolbap/xfon/pkg/cert"
	"github.com/spf13/cobra"
)

var (
	// simplified subject fields
	commonName         string
	organization       string
	organizationalUnit string

	validityDays int
	isCA         bool

	keyUsages    []string
	extKeyUsages []string
	usage        x509.KeyUsage
	extUsage     x509.ExtKeyUsage

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

	// NewCmd.PersistentFlags().StringVar(&name, "name", "ca", "name for generated certificate files")
	// NewCmd.PersistentFlags().StringVar(&path, "path", "", "path for the generated assets (must exist)")

	// subject
	NewCmd.Flags().StringVar(&commonName, "common-name", "", "CN for certificate")
	NewCmd.Flags().StringVar(&organization, "organization", "", "O for certificate")
	NewCmd.Flags().StringVar(&organizationalUnit, "organizational-unit", "", "OU for certificate")

	// features
	NewCmd.Flags().IntVar(&validityDays, "validity-days", 0, "number of validity days for the generated certificate")
	NewCmd.MarkFlagRequired("validity-days")
	NewCmd.Flags().BoolVar(&isCA, "ca", false, "[true|false] wether the certificate is a CA")
	NewCmd.Flags().StringArrayVar(&keyUsages, "usages", []string{}, "key usages for the certificate")
	NewCmd.Flags().StringArrayVar(&extKeyUsages, "ex-usages", []string{}, "extended key usages for the certificate")

	RootCmd.AddCommand(NewCmd)
	RootCmd.AddCommand(SignCmd)
}

func newFuncVal(cmd *cobra.Command, args []string) error {

	var err error
	usage, err = cert.StringArrayToKeyUsage(keyUsages)
	if err != nil {
		return fmt.Errorf("error parsing key usage: %+v", err)
	}

	extUsage, err = cert.StringArrayToExtKeyUsage(extKeyUsages)
	if err != nil {
		return fmt.Errorf("error parsing extended key usage: %+v", err)
	}

	return nil
}

// newFunc runs the new RSA command
func newFunc(cmd *cobra.Command, args []string) {
	// Generate certificate
	// get pem encoded key
	// get pem encoded public
	// write key
	// write certificate
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
		KeyUsage:    0,
		ExtKeyUsage: 0,
	}
	err := cert.GenerateX509SelfSignedCertificate(x, nil)
	if err != nil {
		log.Printf("error generating RSA key: %v", err.Error())
		os.Exit(-1)
	}
	log.Printf("debugging: %+v", x)

	// p, err := cert.RSAtoPEM(k)
	// if err != nil {
	// 	log.Printf("error serializing RSA key into PEM: %v", err.Error())
	// 	os.Exit(-1)
	// }

	// err = writeCertFile(out, p)
	// if err != nil {
	// 	log.Printf("error writing RSA key to file: %v", err.Error())
	// 	os.Exit(-1)
	// }
}
