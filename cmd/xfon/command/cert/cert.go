package cert

import (
	"crypto/x509"
	"fmt"
	"log"
	"math/big"
	"net"
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

	// addresses
	dnsAddressList string
	ipAddressList  string
	dnsList        []string
	ipList         []net.IP

	// in and out
	keyIn      string
	certOut    string
	signingKey string
	parentCert string

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
		Run:   newRun,
		Args:  newVal,
	}

	// SignCmd manages private keys
	SignCmd = &cobra.Command{
		Use:   "signed",
		Short: "creates a signed certificate pair",
		Run:   signedRun,
		Args:  signedVal,
	}
)

func runHelp(cmd *cobra.Command, args []string) {
	cmd.Help()
}

func init() {

	// Params for NewCmd

	// subject
	NewCmd.Flags().StringVar(&commonName, "common-name", "", "CN for certificate")
	NewCmd.Flags().StringVar(&organization, "organization", "", "O for certificate")
	NewCmd.Flags().StringVar(&organizationalUnit, "organizational-unit", "", "OU for certificate")

	// features
	NewCmd.Flags().IntVar(&validityDays, "days", 0, "number of validity days for the generated certificate")
	NewCmd.MarkFlagRequired("days")
	NewCmd.Flags().BoolVar(&isCA, "ca", false, "[true|false] wether the certificate is a CA")
	NewCmd.Flags().StringVar(&keyUsages, "usages", "", "comma separated key usages for the certificate")
	NewCmd.Flags().StringVar(&extKeyUsages, "ext-usages", "", "comma separated extended key usages for the certificate")

	// addresses
	NewCmd.PersistentFlags().StringVar(&dnsAddressList, "dns-addresses", "", "comma separated list of name addresses")
	NewCmd.PersistentFlags().StringVar(&ipAddressList, "ip-addresses", "", "comma separated list of ip addresses")

	// in and out
	NewCmd.Flags().StringVar(&keyIn, "key-in", "", "path to key")
	NewCmd.MarkFlagRequired("key-in")
	NewCmd.Flags().StringVar(&certOut, "cert-out", "", "generated certificate file path")
	NewCmd.MarkFlagRequired("cert-out")

	// Params for SignCmd

	// subject
	SignCmd.Flags().StringVar(&commonName, "common-name", "", "CN for certificate")
	SignCmd.Flags().StringVar(&organization, "organization", "", "O for certificate")
	SignCmd.Flags().StringVar(&organizationalUnit, "organizational-unit", "", "OU for certificate")

	// features
	SignCmd.Flags().IntVar(&validityDays, "days", 0, "number of validity days for the generated certificate")
	SignCmd.MarkFlagRequired("days")
	SignCmd.Flags().StringVar(&keyUsages, "usages", "", "comma separated key usages for the certificate")
	SignCmd.Flags().StringVar(&extKeyUsages, "ext-usages", "", "comma separated extended key usages for the certificate")

	// addresses
	SignCmd.PersistentFlags().StringVar(&dnsAddressList, "dns-addresses", "", "comma separated list of name addresses")
	SignCmd.PersistentFlags().StringVar(&ipAddressList, "ip-addresses", "", "comma separated list of ip addresses")

	// in and out
	SignCmd.Flags().StringVar(&keyIn, "key-in", "", "path to key")
	SignCmd.MarkFlagRequired("key-in")
	SignCmd.Flags().StringVar(&certOut, "cert-out", "", "generated certificate file path")
	SignCmd.MarkFlagRequired("cert-out")
	SignCmd.Flags().StringVar(&signingKey, "signing-key", "", "path to key used for signing")
	SignCmd.MarkFlagRequired("signing-key")
	SignCmd.Flags().StringVar(&parentCert, "parent-cert", "", "path to parent cert")
	SignCmd.MarkFlagRequired("parent-cert")

	RootCmd.AddCommand(NewCmd)
	RootCmd.AddCommand(SignCmd)
}

// newVal validates parameters for the new self signed certificate command
func newVal(cmd *cobra.Command, args []string) error {

	var err error
	usage, err = cert.StringToKeyUsage(keyUsages)
	if err != nil {
		return fmt.Errorf("error parsing key usage: %+v", err)
	}

	extUsage, err = cert.StringToExtKeyUsage(extKeyUsages)
	if err != nil {
		return fmt.Errorf("error parsing extended key usage: %+v", err)
	}

	ipList, err = cert.StringToIPAddressList(ipAddressList)
	if err != nil {
		return fmt.Errorf("error parsing extended key usage: %+v", err)
	}

	dnsList = cert.StringToDNSAddressList(dnsAddressList)

	return nil
}

// newRun runs the new self signed certificate command
func newRun(cmd *cobra.Command, args []string) {
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
		DNSNames:    dnsList,
		IPAddresses: ipList,
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

// signedVal validates the signed certificate command
func signedVal(cmd *cobra.Command, args []string) error {

	var err error
	usage, err = cert.StringToKeyUsage(keyUsages)
	if err != nil {
		return fmt.Errorf("error parsing key usage: %+v", err)
	}

	extUsage, err = cert.StringToExtKeyUsage(extKeyUsages)
	if err != nil {
		return fmt.Errorf("error parsing extended key usage: %+v", err)
	}

	ipList, err = cert.StringToIPAddressList(ipAddressList)
	if err != nil {
		return fmt.Errorf("error parsing extended key usage: %+v", err)
	}

	dnsList = cert.StringToDNSAddressList(dnsAddressList)

	return nil
}

// signedRun runs the signed certificate command
func signedRun(cmd *cobra.Command, args []string) {
	ki, err := filesystem.ReadContentsFromFile(keyIn)
	if err != nil {
		log.Printf("error reading key %q: %v", keyIn, err.Error())
		os.Exit(-1)
	}

	key, err := rsa.ReadPEM(ki)
	if err != nil {
		log.Printf("no key found at %q: %v", keyIn, err.Error())
		os.Exit(-1)
	}

	pc, err := filesystem.ReadContentsFromFile(parentCert)
	if err != nil {
		log.Printf("error reading parent cert %q: %v", parentCert, err.Error())
		os.Exit(-1)
	}

	parent, err := cert.ReadPEM(pc)
	if err != nil {
		log.Printf("no cert found at %q: %v", parentCert, err.Error())
		os.Exit(-1)
	}

	sk, err := filesystem.ReadContentsFromFile(signingKey)
	if err != nil {
		log.Printf("error reading signing key %q: %v", signingKey, err.Error())
		os.Exit(-1)
	}

	signing, err := rsa.ReadPEM(sk)
	if err != nil {
		log.Printf("no key found at %q: %v", signingKey, err.Error())
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
		DNSNames:    dnsList,
		IPAddresses: ipList,
		Serial:      new(big.Int).SetInt64(0),
		NotBefore:   tb,
		NotAfter:    ta,
		IsCA:        isCA,
		KeyUsage:    usage,
		ExtKeyUsage: extUsage,
	}

	// b, err := cert.GenerateX509SelfSignedCertificate(x, key)
	b, err := cert.GenerateX509Certificate(x, parent, key, signing)
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
