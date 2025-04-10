package display

import (
	"fmt"
	"strings"

	"github.com/harekrishnarai/depcheck/pkg/version"
	"github.com/fatih/color"
)

// DisplayVulnerabilities displays vulnerability information in a formatted way
func DisplayVulnerabilities(vulns []version.CVEDetails) {
	for _, vuln := range vulns {
		// Format severity with color
		severity := fmt.Sprintf("%s (%.1f)", vuln.Severity, vuln.Score)
		switch vuln.Severity {
		case "Critical":
			severity = color.RedString("%s (%.1f)", vuln.Severity, vuln.Score)
		case "High":
			severity = color.HiRedString("%s (%.1f)", vuln.Severity, vuln.Score)
		case "Medium":
			severity = color.YellowString("%s (%.1f)", vuln.Severity, vuln.Score)
		case "Low":
			severity = color.GreenString("%s (%.1f)", vuln.Severity, vuln.Score)
		}

		// Display vulnerability information
		fmt.Printf("  %s: %s\n", color.CyanString(vuln.ID), color.HiWhiteString(vuln.Description))
		fmt.Printf("    Severity: %s\n", severity)
		fmt.Printf("    Fixed In: %s\n", color.YellowString(vuln.FixedIn))
		if vuln.Details != "" {
			fmt.Printf("    Details: %s\n", vuln.Details)
		}
		
		// Display links
		var links []string
		if strings.HasPrefix(vuln.ID, "CVE-") {
			links = append(links, fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", vuln.ID))
		}
		if strings.HasPrefix(vuln.ID, "GHSA-") {
			links = append(links, fmt.Sprintf("https://github.com/advisories/%s", vuln.ID))
		}
		if vuln.URL != "" {
			links = append(links, vuln.URL)
		}
		if len(links) > 0 {
			fmt.Printf("    References:\n")
			for _, link := range links {
				fmt.Printf("      - %s\n", color.BlueString(link))
			}
		}
		fmt.Println()
	}
} 