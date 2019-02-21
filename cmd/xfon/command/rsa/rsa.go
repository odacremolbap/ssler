package rsa

import "github.com/spf13/cobra"

var (
	bits int

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
		Run:   runHelp,
	}
)

func runHelp(cmd *cobra.Command, args []string) {
	cmd.Help()
}

func init() {
	NewCmd.PersistentFlags().IntVar(&bits, "bits", 4096, "key size")
	RootCmd.AddCommand(NewCmd)
}
