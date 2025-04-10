package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/harekrishnarai/depcheck/pkg/version"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"github.com/fatih/color"
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
		headers := []string{"Package", "Current", "Latest", "Patched", "Breaking Changes", "Security", "Recommendation"}
		colors := []tablewriter.Colors{
			{tablewriter.FgHiCyanColor},    // Package
			{tablewriter.FgYellowColor},    // Current
			{tablewriter.FgGreenColor},     // Latest
			{tablewriter.FgHiYellowColor},  // Patched
			{tablewriter.FgRedColor},       // Breaking Changes
			{tablewriter.FgMagentaColor},   // Security
			{tablewriter.FgHiWhiteColor},   // Recommendation
		}
		
		table.SetHeader(headers)
		table.SetHeaderColor(colors...)
		
		// Improve table formatting
		table.SetAutoWrapText(true)
		table.SetRowLine(false)
		table.SetColumnSeparator("│")
		table.SetCenterSeparator("─")
		table.SetRowSeparator("─")
		table.SetAlignment(tablewriter.ALIGN_LEFT)
		table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
		table.SetBorder(true)

		breakingChanges := color.GreenString("No")
		if analysis.HasBreakingChanges {
			breakingChanges = color.RedString("Yes")
		}

		securityStatus := "None"
		if analysis.HasBreakingChanges {
			securityStatus = color.RedString("High")
		} else if analysis.Latest != analysis.Current {
			securityStatus = color.YellowString("Medium")
		} else {
			securityStatus = color.GreenString("None")
		}

		table.Append([]string{
			color.CyanString(analysis.Name),
			color.YellowString(analysis.Current),
			color.GreenString(analysis.Latest),
			color.HiYellowString(analysis.Patched),
			breakingChanges,
			securityStatus,
			analysis.Recommendation,
		})

		table.Render()
		return nil
	},
}

func init() {
	rootCmd.AddCommand(checkCmd)
} 