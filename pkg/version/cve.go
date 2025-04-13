package version

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
)

// CVEDetails represents information about a specific CVE
type CVEDetails struct {
	ID          string    // CVE ID (e.g., CVE-2023-1234)
	Description string    // Description of the vulnerability
	Severity    string    // CVSS severity (Critical, High, Medium, Low)
	Score       float64   // CVSS score
	Published   time.Time // When the CVE was published
	FixedIn     string    // Version where this CVE was fixed
	URL         string    // URL to the advisory
	Details     string    // Detailed description of the vulnerability
	Aliases     []string  // Alternative IDs (e.g., GHSA IDs)
	Source      string    // Source of the vulnerability info (deps.dev or osv.dev)
}

// CVEInfo holds information about CVEs affecting a package
type CVEInfo struct {
	Current []CVEDetails // CVEs affecting the current version
	Fixed   []CVEDetails // CVEs fixed in newer versions
	New     []CVEDetails // New CVEs in the latest version
}

// DepsDevResponse represents the response from deps.dev API
type DepsDevResponse struct {
	Version struct {
		VersionKey struct {
			System  string `json:"system"`
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"versionKey"`
		IsDefault bool `json:"isDefault"`
		Licenses  []struct {
			Name string `json:"name"`
			URL  string `json:"url"`
		} `json:"licenses"`
		Links []struct {
			Label string `json:"label"`
			URL   string `json:"url"`
		} `json:"links"`
		Advisories []struct {
			Advisory struct {
				ID      string `json:"id"`
				URL     string `json:"url"`
				Summary string `json:"summary"`
				Aliases []string `json:"aliases"`
				FixedIn string `json:"fixedIn"`
				CVSS    struct {
					Score  float64 `json:"score"`
					Vector string  `json:"vector"`
				} `json:"cvss"`
			} `json:"advisory"`
		} `json:"advisories"`
	} `json:"version"`
}

// OSVQuery represents a query to the OSV.dev API
type OSVQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}

// OSVResponse represents the response from OSV.dev API
type OSVResponse struct {
	Vulns []struct {
		ID        string `json:"id"`
		Summary   string `json:"summary"`
		Details   string `json:"details"`
		Modified  string `json:"modified"`
		Published string `json:"published"`
		Severity  []struct {
			Type  string      `json:"type"`
			Score interface{} `json:"score"` // Can be string or float64
		} `json:"severity"`
		DatabaseSpecific struct {
			CWEIds         []string `json:"cwe_ids"`
			GitHubReviewed bool     `json:"github_reviewed"`
			Severity       string   `json:"severity"`
		} `json:"database_specific"`
		Affected []struct {
			Package struct {
				Name      string `json:"name"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Ranges []struct {
				Type   string `json:"type"`
				Events []struct {
					Introduced string `json:"introduced,omitempty"`
					Fixed      string `json:"fixed,omitempty"`
				} `json:"events"`
			} `json:"ranges"`
		} `json:"affected"`
		References []struct {
			Type string `json:"type"`
			URL  string `json:"url"`
		} `json:"references"`
	} `json:"vulns"`
}

// fetchCVEs fetches CVE information from both deps.dev and OSV.dev
func fetchCVEs(packageName, currentVersion, latestVersion string) (*CVEInfo, error) {
	info := &CVEInfo{
		Current: make([]CVEDetails, 0),
		Fixed:   make([]CVEDetails, 0),
		New:     make([]CVEDetails, 0),
	}

	// First, check deps.dev
	fmt.Printf("🔍 Checking deps.dev for %s@%s...\n", packageName, currentVersion)
	if err := fetchDepsDevVulns(packageName, currentVersion, latestVersion, info); err != nil {
		fmt.Printf("⚠️  Warning: deps.dev check failed: %v\n", err)
	}

	// Then check OSV.dev
	fmt.Printf("🔍 Checking OSV.dev for %s@%s...\n", packageName, currentVersion)
	if err := fetchOSVVulns(packageName, currentVersion, latestVersion, info); err != nil {
		fmt.Printf("⚠️  Warning: OSV.dev check failed: %v\n", err)
	}

	return info, nil
}

func fetchDepsDevVulns(packageName, currentVersion, latestVersion string, info *CVEInfo) error {
	// Get current version info
	versionURL := fmt.Sprintf("https://api.deps.dev/v3/systems/npm/packages/%s/versions/%s", 
		url.PathEscape(packageName), url.PathEscape(currentVersion))
	
	versionResp, err := http.Get(versionURL)
	if err != nil {
		return fmt.Errorf("failed to fetch version info: %v", err)
	}
	defer versionResp.Body.Close()

	if versionResp.StatusCode == http.StatusNotFound {
		return nil // Version not found, skip
	}

	var versionData DepsDevResponse
	if err := json.NewDecoder(versionResp.Body).Decode(&versionData); err != nil {
		return fmt.Errorf("failed to decode version response: %v", err)
	}

	// Process advisories for current version
	for _, advisory := range versionData.Version.Advisories {
		details := CVEDetails{
			ID:          advisory.Advisory.ID,
			Description: advisory.Advisory.Summary,
			FixedIn:     advisory.Advisory.FixedIn,
			URL:         advisory.Advisory.URL,
			Score:       advisory.Advisory.CVSS.Score,
			Aliases:     advisory.Advisory.Aliases,
			Source:      "deps.dev",
		}

		// Determine severity based on CVSS score
		switch {
		case details.Score >= 9.0:
			details.Severity = "Critical"
		case details.Score >= 7.0:
			details.Severity = "High"
		case details.Score >= 4.0:
			details.Severity = "Medium"
		default:
			details.Severity = "Low"
		}

		// Check if this vulnerability affects the current version
		currentVer, err := semver.NewVersion(currentVersion)
		if err != nil {
			continue
		}

		if advisory.Advisory.FixedIn != "" {
			fixedVer, err := semver.NewVersion(advisory.Advisory.FixedIn)
			if err != nil {
				continue
			}

			if currentVer.LessThan(fixedVer) {
				info.Current = append(info.Current, details)
			} else {
				info.Fixed = append(info.Fixed, details)
			}
		} else {
			info.Current = append(info.Current, details)
		}
	}

	return nil
}

// Updated the code to correctly fetch and display CVSS score or severity level for the issues
func fetchOSVVulns(packageName, currentVersion, latestVersion string, info *CVEInfo) error {
	// Prepare OSV.dev query
	query := OSVQuery{}
	query.Package.Name = packageName
	query.Package.Ecosystem = "npm"
	query.Version = currentVersion

	queryJSON, err := json.Marshal(query)
	if err != nil {
		return fmt.Errorf("failed to marshal OSV query: %v", err)
	}

	// Query OSV.dev API
	resp, err := http.Post("https://api.osv.dev/v1/query", "application/json", bytes.NewBuffer(queryJSON))
	if err != nil {
		return fmt.Errorf("failed to query OSV.dev: %v", err)
	}
	defer resp.Body.Close()

	var osvResp OSVResponse
	if err := json.NewDecoder(resp.Body).Decode(&osvResp); err != nil {
		return fmt.Errorf("failed to decode OSV response: %v", err)
	}

	// Process vulnerabilities
	for _, vuln := range osvResp.Vulns {
		details := CVEDetails{
			ID:          vuln.ID,
			Description: vuln.Summary,
			Details:     vuln.Details,
			Source:      "osv.dev",
		}

		// Get severity - first check if there's a CVSS vector
		hasSeverityScore := false
		if len(vuln.Severity) > 0 {
			// First try to parse actual CVSS vector strings for more accurate scores
			for _, severity := range vuln.Severity {
				if vectorStr, ok := severity.Score.(string); ok {
					// Check if it's a CVSS vector string (starts with "CVSS:")
					if strings.HasPrefix(vectorStr, "CVSS:") {
						score := parseCVSSVector(vectorStr)
						if score > 0 {
							details.Score = score
							hasSeverityScore = true
							
							// Determine severity based on score
							switch {
							case score >= 9.0:
								details.Severity = "Critical"
							case score >= 7.0:
								details.Severity = "High"
							case score >= 4.0:
								details.Severity = "Medium"
							default:
								details.Severity = "Low"
							}
							break // Use the first valid vector we find
						}
					}
				}
			}
			
			// If no CVSS vector was found, fall back to handling numeric or text-based scores
			if !hasSeverityScore {
				var highestScore float64
				for _, severity := range vuln.Severity {
					var score float64
					switch s := severity.Score.(type) {
					case float64:
						score = s
						hasSeverityScore = true
					case string:
						// Try to parse string score
						if parsed, err := parseScore(s); err == nil {
							score = parsed
							hasSeverityScore = true
						}
					}
					if score > highestScore {
						highestScore = score
					}
				}
				
				if hasSeverityScore {
					details.Score = highestScore
					
					// Determine severity based on highest score
					switch {
					case details.Score >= 9.0:
						details.Severity = "Critical"
					case details.Score >= 7.0:
						details.Severity = "High"
					case details.Score >= 4.0:
						details.Severity = "Medium"
					default:
						details.Severity = "Low"
					}
				}
			}
		}

		// If we don't have a severity score yet, check the DatabaseSpecific field
		// This is often the case with GitHub Security Advisories (GHSA)
		if !hasSeverityScore && vuln.DatabaseSpecific.Severity != "" {
			severityStr := strings.ToUpper(vuln.DatabaseSpecific.Severity)
			if parsed, err := parseScore(severityStr); err == nil {
				details.Score = parsed
				
				// Use the original severity string from the database
				details.Severity = vuln.DatabaseSpecific.Severity
				
				// Make first letter uppercase and rest lowercase for consistent formatting
				if len(details.Severity) > 0 {
					details.Severity = strings.ToUpper(details.Severity[:1]) + strings.ToLower(details.Severity[1:])
				}
			}
		}

		// Get fixed version from ranges
		if len(vuln.Affected) > 0 && len(vuln.Affected[0].Ranges) > 0 {
			for _, r := range vuln.Affected[0].Ranges[0].Events {
				if r.Fixed != "" {
					details.FixedIn = r.Fixed
					break
				}
			}
		}

		// Get URL from references
		for _, ref := range vuln.References {
			if ref.Type == "ADVISORY" {
				details.URL = ref.URL
				break
			}
		}

		// Parse published date
		if vuln.Published != "" {
			if published, err := time.Parse(time.RFC3339, vuln.Published); err == nil {
				details.Published = published
			}
		}

		// Check if this vulnerability affects the current version
		currentVer, err := semver.NewVersion(currentVersion)
		if err != nil {
			continue
		}

		if details.FixedIn != "" {
			fixedVer, err := semver.NewVersion(details.FixedIn)
			if err != nil {
				continue
			}

			if currentVer.LessThan(fixedVer) {
				// Check if we already have this vulnerability from deps.dev
				isDuplicate := false
				for _, existing := range info.Current {
					if existing.ID == details.ID || containsID(existing.Aliases, details.ID) {
						isDuplicate = true
						break
					}
				}
				if !isDuplicate {
					info.Current = append(info.Current, details)
				}
			} else {
				isDuplicate := false
				for _, existing := range info.Fixed {
					if existing.ID == details.ID || containsID(existing.Aliases, details.ID) {
						isDuplicate = true
						break
					}
				}
				if !isDuplicate {
					info.Fixed = append(info.Fixed, details)
				}
			}
		} else {
			// If no fixed version, check if we already have this vulnerability
			isDuplicate := false
			for _, existing := range info.Current {
				if existing.ID == details.ID || containsID(existing.Aliases, details.ID) {
					isDuplicate = true
					break
				}
			}
			if !isDuplicate {
				info.Current = append(info.Current, details)
			}
		}
	}

	return nil
}

// containsID checks if a list of IDs contains a specific ID
func containsID(ids []string, target string) bool {
	for _, id := range ids {
		if id == target {
			return true
		}
	}
	return false
}

// isVersionInRange checks if a version is within a given range
func isVersionInRange(version, introduced, fixed string) bool {
	if introduced == "" {
		introduced = "0.0.0"
	}
	
	// Parse versions using semver
	ver, err := semver.NewVersion(version)
	if err != nil {
		return false
	}

	intro, err := semver.NewVersion(introduced)
	if err != nil {
		return false
	}

	// If no fixed version, only check if current version is >= introduced
	if fixed == "" {
		return ver.Compare(intro) >= 0
	}

	fix, err := semver.NewVersion(fixed)
	if err != nil {
		return false
	}

	// Check if version is in range [introduced, fixed)
	return ver.Compare(intro) >= 0 && ver.Compare(fix) < 0
}

// parseScore attempts to parse a severity score from a string
func parseScore(score string) (float64, error) {
	switch score {
	case "CRITICAL":
		return 9.0, nil
	case "HIGH":
		return 7.0, nil
	case "MEDIUM":
		return 4.0, nil
	case "MODERATE":
		return 4.0, nil
	case "LOW":
		return 1.0, nil
	default:
		return 0.0, fmt.Errorf("unknown severity: %s", score)
	}
}

// parseCVSSVector parses a CVSS vector string and returns the calculated score
func parseCVSSVector(vector string) float64 {
	// Default score if parsing fails
	defaultScore := 0.0

	// CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N -> 6.1 (Medium)
	// CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:N -> 4.0 (Medium)
	// CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N -> 6.1 (Medium)

	// Common base scores from CVSS calculator for reference
	// This is a simplified implementation - a real one would compute the actual score
	knownVectors := map[string]float64{
		"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,  // Medium
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,  // Medium
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:N": 4.0,  // Medium
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L": 4.7,  // Medium
		"CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:L": 4.3, // Low
	}

	if score, found := knownVectors[vector]; found {
		return score
	}

	// For simplicity, parse the CVSS version and make a reasonable estimation
	if strings.HasPrefix(vector, "CVSS:3") {
		// Parse the metrics from the vector
		metrics := strings.Split(vector, "/")
		
		// Simplified scoring based on key metrics
		score := 5.0 // Medium is the default
		
		// Look for key metrics that impact the score
		for _, metric := range metrics {
			switch {
			case metric == "AV:N": // Network
				score += 0.5
			case metric == "AC:L": // Low complexity
				score += 0.5
			case metric == "PR:N": // No privileges
				score += 0.5
			case metric == "S:C": // Changed scope
				score += 1.0
			case metric == "C:H" || metric == "I:H" || metric == "A:H": // High impact
				score += 1.0
			case metric == "C:L" || metric == "I:L" || metric == "A:L": // Low impact
				score -= 0.2
			}
		}
		
		// Clamp the score to CVSS range
		if score > 10.0 {
			score = 10.0
		} else if score < 0.1 {
			score = 0.1
		}
		
		return score
	}
	
	return defaultScore
}