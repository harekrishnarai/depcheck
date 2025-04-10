package cmd

import (
	"fmt"
	"os"

	"github.com/harekrishnarai/depcheck/pkg/version"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"github.com/fatih/color"
)

var fileCmd = &cobra.Command{
	Use:   "file [path]",
	Short: "Check dependencies from a package file",
	Long: `Check dependencies from a package file (e.g., package.json, requirements.txt).
The tool will automatically detect the file type and check all dependencies.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]
		
		// Check if file exists
		file, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("failed to open file %s: %v", filePath, err)
		}
		defer file.Close()

		// Analyze the package file
		analyses, err := version.AnalyzePackageFile(file)
		if err != nil {
			return fmt.Errorf("failed to analyze package file: %v", err)
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

		for _, analysis := range analyses {
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
		}

		table.Render()
		return nil
	},
}

func init() {
	rootCmd.AddCommand(fileCmd)
} 