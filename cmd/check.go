package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/harekrishnarai/depcheck/pkg/version"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

var checkCmd = &cobra.Command{
	Use:   "check [package]@[version]",
	Short: "Check if a specific package version exists",
	Long: `Check if a specific package version exists in the package registry.
Example: depcheck check express@4.18.2`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		packageSpec := args[0]
		parts := strings.Split(packageSpec, "@")
		if len(parts) != 2 {
			return fmt.Errorf("invalid package specification. Use format: package@version")
		}

		pkgName := parts[0]
		pkgVersion := parts[1]

		analysis, err := version.AnalyzePackage(pkgName, pkgVersion)
		if err != nil {
			return fmt.Errorf("failed to analyze package: %v", err)
		}

		// Create and display the table
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Package", "Current", "Latest", "Patched", "Breaking Changes", "Security Implications", "Recommendation"})
		
		// Improve table formatting
		table.SetAutoWrapText(true)
		table.SetRowLine(false)
		table.SetColumnSeparator("|")
		table.SetCenterSeparator("+")
		table.SetRowSeparator("-")
		table.SetAlignment(tablewriter.ALIGN_LEFT)
		table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
		table.SetBorder(true)

		breakingChanges := "No"
		if analysis.HasBreakingChanges {
			breakingChanges = "Yes"
		}

		table.Append([]string{
			analysis.Name,
			analysis.Current,
			analysis.Latest,
			analysis.Patched,
			breakingChanges,
			analysis.SecurityImplications,
			analysis.Recommendation,
		})

		table.Render()
		return nil
	},
}

func init() {
	rootCmd.AddCommand(checkCmd)
} 