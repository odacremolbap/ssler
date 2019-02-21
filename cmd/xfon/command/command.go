package command

import (
	"os"

	"github.com/odacremolbap/xfon/cmd/xfon/command/rsa"
	"github.com/odacremolbap/xfon/cmd/xfon/command/x509"

	"github.com/spf13/cobra"
)

var (
	// XfonCmd is the base command
	XfonCmd = &cobra.Command{
		Use:   "xfon",
		Short: "X509 minimal functionality command",
		Run:   runHelp,
	}
)

func init() {
	XfonCmd.PersistentFlags().IntP("v", "v", 1, "verbosity level")
	XfonCmd.AddCommand(x509.RootCmd)
	XfonCmd.AddCommand(rsa.RSACmd)
}

// Execute base command
func Execute() {

	if err := XfonCmd.Execute(); err != nil {
		os.Exit(-1)
	}
}

func runHelp(cmd *cobra.Command, args []string) {
	cmd.Help()
}
