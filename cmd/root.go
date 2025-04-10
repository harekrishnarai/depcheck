package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "depcheck",
	Short: "A tool to check dependency versions across different package ecosystems",
	Long: `DepCheck is a CLI tool that helps you verify if specific package versions exist
in various package ecosystems. It can check:
- Node.js packages from package.json
- Python packages from requirements.txt
- Single package versions directly`,
}

func Execute() error {
	return rootCmd.Execute()
} 