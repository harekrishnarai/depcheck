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

		fmt.Printf("📦 Reading dependencies from %s...\n", filePath)

		// Analyze the package file
		analyses, err := version.AnalyzePackageFile(file)
		if err != nil {
			return fmt.Errorf("failed to analyze package file: %v", err)
		}

		fmt.Println("\n📊 Analysis Results")
		fmt.Println("══════════════════")

		// Create and display the main package info table
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"PACKAGE", "CURRENT", "LATEST", "PATCHED", "BREAKING CHANGES", "SECURITY", "RECOMMENDATION"})
		
		// Improve table formatting
		table.SetAutoWrapText(false)
		table.SetRowLine(false)
		table.SetColumnSeparator("│")
		table.SetCenterSeparator("┼")
		table.SetRowSeparator("─")
		table.SetHeaderLine(true)
		table.SetBorders(tablewriter.Border{Left: true, Top: true, Right: true, Bottom: true})
		table.SetAlignment(tablewriter.ALIGN_LEFT)
		table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)

		for _, analysis := range analyses {
			breakingChanges := "No"
			if analysis.HasBreakingChanges {
				breakingChanges = color.RedString("Yes")
			}

			// Determine security status based on CVE information
			securityStatus := color.GreenString("✓ Secure")
			recommendation := "Up to date"
			
			if len(analysis.CVEs.Current) > 0 {
				securityStatus = color.RedString(fmt.Sprintf("⚠ %d active CVEs", len(analysis.CVEs.Current)))
				recommendation = color.YellowString("Upgrade recommended")
			}

			table.Append([]string{
				color.CyanString(analysis.Name),
				analysis.Current,
				color.GreenString(analysis.Latest),
				color.YellowString(analysis.Patched),
				breakingChanges,
				securityStatus,
				recommendation,
			})
		}

		table.Render()
		fmt.Println()

		// Display vulnerability information for each package
		for _, analysis := range analyses {
			if len(analysis.CVEs.Current) > 0 {
				fmt.Printf("🔒 Security Analysis for %s\n", color.CyanString(analysis.Name))
				fmt.Println("═══════════════════════════")
				
				// Create vulnerability table
				vulnTable := tablewriter.NewWriter(os.Stdout)
				vulnTable.SetHeader([]string{"ADVISORY", "SEVERITY", "FIXED IN", "SOURCE", "LINKS"})
				vulnTable.SetAutoWrapText(false)
				vulnTable.SetRowLine(false)
				vulnTable.SetColumnSeparator("│")
				vulnTable.SetCenterSeparator("┼")
				vulnTable.SetRowSeparator("─")
				vulnTable.SetHeaderLine(true)
				vulnTable.SetBorders(tablewriter.Border{Left: true, Top: true, Right: true, Bottom: true})
				vulnTable.SetAlignment(tablewriter.ALIGN_LEFT)
				vulnTable.SetHeaderAlignment(tablewriter.ALIGN_LEFT)

				for _, vuln := range analysis.CVEs.Current {
					// Format severity with color and emoji
					severity := "🟢 " + color.GreenString("Low")
					switch strings.ToLower(vuln.Severity) {
					case "critical":
						severity = "🔴 " + color.RedString("Critical")
					case "high":
						severity = "🟣 " + color.HiRedString("High")
					case "medium":
						severity = "🟡 " + color.YellowString("Medium")
					}

					// Format source with icon
					source := "🔍 deps.dev"
					if vuln.Source == "osv.dev" {
						source = "🛡️ osv.dev"
					}

					// Format links
					var link string
					if strings.HasPrefix(vuln.ID, "GHSA-") {
						link = fmt.Sprintf("https://github.com/advisories/%s", vuln.ID)
					} else if strings.HasPrefix(vuln.ID, "CVE-") {
						link = fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", vuln.ID)
					} else {
						link = vuln.URL
					}

					vulnTable.Append([]string{
						color.CyanString(vuln.ID),
						severity,
						color.YellowString(vuln.FixedIn),
						source,
						color.BlueString(link),
					})
				}
				vulnTable.Render()

				// Show recommendation
				fmt.Printf("\n📝 %s\n", color.HiWhiteString("Recommendation"))
				fmt.Printf("   %s to version %s to fix %d vulnerabilities\n",
					color.YellowString("Upgrade"),
					color.GreenString(analysis.Patched),
					len(analysis.CVEs.Current))
				fmt.Println()
			}
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(fileCmd)
} 