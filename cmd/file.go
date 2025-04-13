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
		
		fmt.Printf("📦 Reading dependencies from %s...\n", filePath)

		var analyses []version.PackageAnalysis
		
		// Check if the provided file is a lock file
		isLockFile := strings.HasSuffix(filePath, "package-lock.json") || 
			strings.HasSuffix(filePath, "yarn.lock") || 
			strings.HasSuffix(filePath, "npm-shrinkwrap.json")
			
		if isLockFile {
			// If this is a lock file, analyze it directly
			file, fileErr := os.Open(filePath)
			if fileErr != nil {
				return fmt.Errorf("failed to open file %s: %v", filePath, fileErr)
			}
			defer file.Close()
			
			var parseErr error
			// Determine the type of lock file and analyze accordingly
			if strings.HasSuffix(filePath, "package-lock.json") || strings.HasSuffix(filePath, "npm-shrinkwrap.json") {
				analyses, parseErr = version.AnalyzeNpmLockFile(file)
				if parseErr != nil {
					return fmt.Errorf("failed to analyze npm lock file: %v", parseErr)
				}
			} else if strings.HasSuffix(filePath, "yarn.lock") {
				analyses, parseErr = version.AnalyzeYarnLockFile(file)
				if parseErr != nil {
					return fmt.Errorf("failed to analyze yarn lock file: %v", parseErr)
				}
			}
		} else {
			// If not a lock file, try to find an associated lock file or fall back to the provided file
			// Try to use lock file for more accurate version info
			lockFileAnalyses, lockErr := version.FindAndAnalyzeLockFile(filePath)
			if lockErr == nil {
				// Lock file found and analyzed successfully
				analyses = lockFileAnalyses
			} else {
				// No lock file or error parsing it, fall back to package file
				file, fileErr := os.Open(filePath)
				if fileErr != nil {
					return fmt.Errorf("failed to open file %s: %v", filePath, fileErr)
				}
				defer file.Close()
				
				// Analyze the package file
				var parseErr error
				analyses, parseErr = version.AnalyzePackageFile(file)
				if parseErr != nil {
					return fmt.Errorf("failed to analyze package file: %v", parseErr)
				}
			}
		}

		fmt.Println("\n📊 Analysis Results")
		fmt.Println("══════════════════")

		// Organize dependencies - separate direct and transitive deps
		var directDeps []version.PackageAnalysis
		var transitiveDeps []version.PackageAnalysis

		for _, analysis := range analyses {
			if analysis.IsTransitive {
				transitiveDeps = append(transitiveDeps, analysis)
			} else {
				directDeps = append(directDeps, analysis)
			}
		}

		// Display direct dependencies
		fmt.Println("\n📦 Direct Dependencies")
		displayDependenciesTable(directDeps)

		// If we have transitive dependencies, display them as well
		if len(transitiveDeps) > 0 {
			fmt.Println("\n🔗 Transitive Dependencies")
			displayTransitiveDependenciesTable(transitiveDeps)
		}

		// Display vulnerability information for all dependencies
		for _, analysis := range analyses {
			if len(analysis.CVEs.Current) > 0 {
				fmt.Printf("\n🔒 Security Analysis for %s\n", color.CyanString(analysis.Name))
				
				// Add dependency path info for transitive dependencies
				if analysis.IsTransitive {
					fmt.Printf("   %s: %s\n", color.YellowString("Dependency Path"), analysis.DependencyPath)
				}
				
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
					// Format severity with color and emoji
					severity := "🟢 " + color.GreenString("Low")
					switch strings.ToLower(vuln.Severity) {
					case "critical":
						severity = "🔴 " + color.RedString("Critical")
					case "high":
						severity = "🟣 " + color.HiRedString("High")
					case "medium":
						severity = "🟡 " + color.YellowString("Medium")
					case "moderate":
						severity = "🟡 " + color.YellowString("Moderate")
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

// displayDependenciesTable displays the table of direct dependencies
func displayDependenciesTable(analyses []version.PackageAnalysis) {
	if len(analyses) == 0 {
		fmt.Println("   No direct dependencies found.")
		return
	}

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
}

// displayTransitiveDependenciesTable displays the table of transitive dependencies
func displayTransitiveDependenciesTable(analyses []version.PackageAnalysis) {
	if len(analyses) == 0 {
		fmt.Println("   No transitive dependencies found.")
		return
	}

	// Create and display the transitive dependencies table
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"PACKAGE", "DEPENDENCY PATH", "CURRENT", "LATEST", "SECURITY"})
	
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
		// Determine security status based on CVE information
		securityStatus := color.GreenString("✓ Secure")
		
		if len(analysis.CVEs.Current) > 0 {
			securityStatus = color.RedString(fmt.Sprintf("⚠ %d active CVEs", len(analysis.CVEs.Current)))
		}

		table.Append([]string{
			color.CyanString(analysis.Name),
			color.YellowString(analysis.DependencyPath),
			analysis.Current,
			color.GreenString(analysis.Latest),
			securityStatus,
		})
	}

	table.Render()
}

func init() {
	rootCmd.AddCommand(fileCmd)
}