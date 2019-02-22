package x509

import (
	"log"
	"os"

	"github.com/odacremolbap/xfon/pkg/cert"
	"github.com/spf13/cobra"
)

// RootCmd contains certificate management commands
var RootCmd = &cobra.Command{
	Use:   "x509",
	Short: "x509 manages certificates",
	Run:   runHelp,
}

// NewCmd creates certificate key pair
var NewCmd = &cobra.Command{
	Use:   "new",
	Short: "creates certificate key pair",
	Run:   newFunc,
}

// SignCmd manages private keys
var SignCmd = &cobra.Command{
	Use:   "signed",
	Short: "creates a signed certificate pair",
	Run:   runHelp,
}

func runHelp(cmd *cobra.Command, args []string) {
	cmd.Help()
}

func init() {
	RootCmd.AddCommand(NewCmd)
	RootCmd.AddCommand(SignCmd)
}

// newFunc runs the new RSA command
func newFunc(cmd *cobra.Command, args []string) {
	// Generate certificate
	// get pem encoded key
	// get pem encoded public
	// write key
	// write certificate

	x := &cert.X509{}
	err := cert.GenerateX509SelfSignedCertificate(x, nil)
	if err != nil {
		log.Printf("error generating RSA key: %v", err.Error())
		os.Exit(-1)
	}
	log.Printf("debugging: %v", x)

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
