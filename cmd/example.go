package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// exampleCmd represents an example CLI command
var exampleCmd = &cobra.Command{
	Use:   "example",
	Short: "An example command",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Example command executed via CLI")
	},
}
