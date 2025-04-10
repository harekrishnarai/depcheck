package cmd

import (
	"fmt"
	"os"

	"github.com/harekrishnarai/depcheck/pkg/version"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
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
		table.SetColWidth(40) // Reduced from 50 to make it more compact

		for _, analysis := range analyses {
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
		}

		table.Render()
		return nil
	},
}

func init() {
	rootCmd.AddCommand(fileCmd)
} 