package rsa

import (
	"errors"
	"log"
	"os"

	"github.com/odacremolbap/xfon/pkg/cert"
	"github.com/spf13/cobra"
)

var (
	bits int
	out  string

	// RootCmd manages private keys
	RootCmd = &cobra.Command{
		Use:   "rsa",
		Short: "manages private keys",
		Run:   runHelp,
	}

	// NewCmd creates new RSA key
	NewCmd = &cobra.Command{
		Use:   "new",
		Short: "creates new RSA key",
		Run:   newFunc,
		Args:  newValidator,
	}
)

func runHelp(cmd *cobra.Command, args []string) {
	cmd.Help()
}

func init() {
	NewCmd.Flags().IntVar(&bits, "bits", 4096, "key size")
	NewCmd.Flags().StringVar(&out, "out", "", "RSA key output file")
	NewCmd.MarkFlagRequired("out")
	RootCmd.AddCommand(NewCmd)
}

func newValidator(cmd *cobra.Command, args []string) error {
	if bits > 5000 {
		return errors.New("howdy, testing validation")
	}
	return nil
}

// newFunc runs the new RSA command
func newFunc(cmd *cobra.Command, args []string) {
	k, err := cert.GenerateRSAKey(bits)
	if err != nil {
		log.Printf("error generating RSA key: %v", err.Error())
		os.Exit(-1)
	}

	p, err := cert.RSAtoPEM(k)
	if err != nil {
		log.Printf("error serializing RSA key into PEM: %v", err.Error())
		os.Exit(-1)
	}

	err = writeCertFile(out, p)
	if err != nil {
		log.Printf("error writing RSA key to file: %v", err.Error())
		os.Exit(-1)
	}
}

func writeCertFile(path, contents string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(contents)
	return err
}
