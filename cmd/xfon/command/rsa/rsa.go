package rsa

import "github.com/spf13/cobra"

// RSACmd manages private keys
var RSACmd = &cobra.Command{
	Use:   "rsa",
	Short: "manages private keys",
	Run:   runHelp,
}

func runHelp(cmd *cobra.Command, args []string) {
	cmd.Help()
}
