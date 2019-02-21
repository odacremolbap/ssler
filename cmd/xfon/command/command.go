package command

import (
	"os"

	"github.com/odacremolbap/ssler/cmd/xfon/command/rsa"
	"github.com/odacremolbap/ssler/cmd/xfon/command/x509"

	"github.com/spf13/cobra"
)

var (
	// SSLerCmd is the base command
	SSLerCmd = &cobra.Command{
		Use:   "xfon",
		Short: "X509 minimal functionality command",
		Run:   runHelp,
	}
)

func init() {
	SSLerCmd.PersistentFlags().IntP("v", "v", 1, "verbosity level")
	SSLerCmd.AddCommand(x509.RootCmd)
	SSLerCmd.AddCommand(rsa.RSACmd)
}

// Execute base command
func Execute() {

	if err := SSLerCmd.Execute(); err != nil {
		os.Exit(-1)
	}
}

func runHelp(cmd *cobra.Command, args []string) {
	cmd.Help()
}
