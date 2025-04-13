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
	Use:   "check [package] [version]",
	Short: "Check a specific package version",
	Long: `Check a specific package version for updates and vulnerabilities.
Example: depcheck check express 4.17.1`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		pkgName := args[0]
		pkgVersion := args[1]

		analysis, err := version.AnalyzePackage(pkgName, pkgVersion)
		if err != nil {
			return fmt.Errorf("failed to analyze package: %v", err)
		}

		fmt.Printf("📦 Fetching package info for %s...\n", color.CyanString(pkgName))
		fmt.Printf("🔍 Checking vulnerabilities in version %s...\n", color.YellowString(pkgVersion))
		fmt.Println()

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

		breakingChanges := "No"
		if analysis.HasBreakingChanges {
			breakingChanges = color.RedString("Yes")
		}

		// Determine security status based on CVE information
		securityStatus := color.GreenString("✓ Secure")
		recommendation := "Up to date"
		
		// Find the highest version that fixes all vulnerabilities
		patchedVersion := analysis.Current
		if len(analysis.CVEs.Current) > 0 {
			securityStatus = color.RedString(fmt.Sprintf("⚠ %d active CVEs", len(analysis.CVEs.Current)))
			
			// Find the highest version that fixes all vulnerabilities
			for _, vuln := range analysis.CVEs.Current {
				if version.CompareVersions(vuln.FixedIn, patchedVersion) > 0 {
					patchedVersion = vuln.FixedIn
				}
			}
			
			if analysis.HasBreakingChanges {
				recommendation = color.YellowString(fmt.Sprintf("Review changelog before upgrading to %s", patchedVersion))
			} else {
				recommendation = color.YellowString(fmt.Sprintf("Upgrade to %s", patchedVersion))
			}
		} else if analysis.HasBreakingChanges {
			recommendation = color.YellowString("Review changelog before upgrading")
		} else if analysis.Current != analysis.Latest {
			recommendation = color.GreenString("Safe to upgrade")
		}

		table.Append([]string{
			color.CyanString(analysis.Name),
			analysis.Current,
			color.GreenString(analysis.Latest),
			color.YellowString(patchedVersion),
			breakingChanges,
			securityStatus,
			recommendation,
		})

		table.Render()
		fmt.Println()

		// Display vulnerability information
		if len(analysis.CVEs.Current) > 0 {
			fmt.Printf("🔒 Security Analysis for %s\n", color.CyanString(analysis.Name))
			fmt.Println("═══════════════════════════")
			
			// Create vulnerability table
			vulnTable := tablewriter.NewWriter(os.Stdout)
			vulnTable.SetHeader([]string{"ADVISORY", "SEVERITY", "SCORE", "FIXED IN", "SOURCE", "LINKS"})
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
				// Update severity mapping logic to handle API severity levels like "MODERATE"
				severity := "🟢 " + color.GreenString("Low")
				switch strings.ToLower(vuln.Severity) {
				case "critical":
					severity = "🔴 " + color.RedString("Critical")
				case "high":
					severity = "🟣 " + color.HiRedString("High")
				case "moderate":
					severity = "🟡 " + color.YellowString("Moderate")
				case "medium":
					severity = "🟡 " + color.YellowString("Medium")
				case "low":
					severity = "🟢 " + color.GreenString("Low")
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

				// Format the score
				score := fmt.Sprintf("%.1f", vuln.Score)

				vulnTable.Append([]string{
					color.CyanString(vuln.ID),
					severity,
					score,
					color.YellowString(vuln.FixedIn),
					source,
					color.BlueString(link),
				})
			}
			vulnTable.Render()

			// Show recommendation
			fmt.Printf("\n📝 %s\n", color.HiWhiteString("Recommendation"))
			if analysis.HasBreakingChanges {
				fmt.Printf("   %s to version %s to fix %d vulnerabilities\n",
					color.YellowString("Review changelog and upgrade"),
					color.GreenString(patchedVersion),
					len(analysis.CVEs.Current))
			} else {
				fmt.Printf("   %s to version %s to fix %d vulnerabilities\n",
					color.YellowString("Upgrade"),
					color.GreenString(patchedVersion),
					len(analysis.CVEs.Current))
			}
			fmt.Println()
		}

		// Display fixed vulnerabilities
		if len(analysis.CVEs.Fixed) > 0 {
			fmt.Printf("%s\n", color.HiWhiteString("Vulnerabilities Fixed in Newer Versions"))
			vulnTable := tablewriter.NewWriter(os.Stdout)
			vulnHeaders := []string{"ID", "Severity", "Score", "Description", "Fixed In", "References"}
			vulnColors := []tablewriter.Colors{
				{tablewriter.FgCyanColor},      // ID
				{tablewriter.FgMagentaColor},   // Severity
				{tablewriter.FgYellowColor},    // Score
				{tablewriter.FgWhiteColor},     // Description
				{tablewriter.FgGreenColor},     // Fixed In
				{tablewriter.FgBlueColor},      // References
			}
			
			vulnTable.SetHeader(vulnHeaders)
			vulnTable.SetHeaderColor(vulnColors...)
			vulnTable.SetAutoWrapText(true)
			vulnTable.SetRowLine(false)
			vulnTable.SetColumnSeparator("│")
			vulnTable.SetCenterSeparator("─")
			vulnTable.SetRowSeparator("─")
			vulnTable.SetAlignment(tablewriter.ALIGN_LEFT)
			vulnTable.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
			vulnTable.SetBorder(true)

			for _, vuln := range analysis.CVEs.Fixed {
				severity := vuln.Severity
				switch vuln.Severity {
				case "Critical":
					severity = color.RedString(vuln.Severity)
				case "High":
					severity = color.HiRedString(vuln.Severity)
				case "Medium":
					severity = color.YellowString(vuln.Severity)
				case "Low":
					severity = color.GreenString(vuln.Severity)
				}

				var refs []string
				if strings.HasPrefix(vuln.ID, "CVE-") {
					refs = append(refs, fmt.Sprintf("NVD: https://nvd.nist.gov/vuln/detail/%s", vuln.ID))
				}
				if strings.HasPrefix(vuln.ID, "GHSA-") {
					refs = append(refs, fmt.Sprintf("GitHub: https://github.com/advisories/%s", vuln.ID))
				}
				if vuln.URL != "" {
					refs = append(refs, fmt.Sprintf("Additional: %s", vuln.URL))
				}
				references := strings.Join(refs, "\n")

				vulnTable.Append([]string{
					color.CyanString(vuln.ID),
					severity,
					fmt.Sprintf("%.1f", vuln.Score),
					vuln.Description,
					color.YellowString(vuln.FixedIn),
					color.BlueString(references),
				})
			}
			vulnTable.Render()
			fmt.Println()
		}

		// Display new vulnerabilities in latest version
		if len(analysis.CVEs.New) > 0 {
			fmt.Printf("%s\n", color.HiWhiteString("New Vulnerabilities in Latest Version"))
			vulnTable := tablewriter.NewWriter(os.Stdout)
			vulnHeaders := []string{"ID", "Severity", "Score", "Description", "Fixed In", "References"}
			vulnColors := []tablewriter.Colors{
				{tablewriter.FgCyanColor},      // ID
				{tablewriter.FgMagentaColor},   // Severity
				{tablewriter.FgYellowColor},    // Score
				{tablewriter.FgWhiteColor},     // Description
				{tablewriter.FgGreenColor},     // Fixed In
				{tablewriter.FgBlueColor},      // References
			}
			
			vulnTable.SetHeader(vulnHeaders)
			vulnTable.SetHeaderColor(vulnColors...)
			vulnTable.SetAutoWrapText(true)
			vulnTable.SetRowLine(false)
			vulnTable.SetColumnSeparator("│")
			vulnTable.SetCenterSeparator("─")
			vulnTable.SetRowSeparator("─")
			vulnTable.SetAlignment(tablewriter.ALIGN_LEFT)
			vulnTable.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
			vulnTable.SetBorder(true)

			for _, vuln := range analysis.CVEs.New {
				severity := vuln.Severity
				switch vuln.Severity {
				case "Critical":
					severity = color.RedString(vuln.Severity)
				case "High":
					severity = color.HiRedString(vuln.Severity)
				case "Medium":
					severity = color.YellowString(vuln.Severity)
				case "Low":
					severity = color.GreenString(vuln.Severity)
				}

				var refs []string
				if strings.HasPrefix(vuln.ID, "CVE-") {
					refs = append(refs, fmt.Sprintf("NVD: https://nvd.nist.gov/vuln/detail/%s", vuln.ID))
				}
				if strings.HasPrefix(vuln.ID, "GHSA-") {
					refs = append(refs, fmt.Sprintf("GitHub: https://github.com/advisories/%s", vuln.ID))
				}
				if vuln.URL != "" {
					refs = append(refs, fmt.Sprintf("Additional: %s", vuln.URL))
				}
				references := strings.Join(refs, "\n")

				vulnTable.Append([]string{
					color.CyanString(vuln.ID),
					severity,
					fmt.Sprintf("%.1f", vuln.Score),
					vuln.Description,
					color.YellowString(vuln.FixedIn),
					color.BlueString(references),
				})
			}
			vulnTable.Render()
			fmt.Println()
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(checkCmd)
}
