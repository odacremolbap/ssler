package x509

import "github.com/spf13/cobra"

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
	Run:   runHelp,
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
