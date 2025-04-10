package version

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// CVEDetails represents information about a specific CVE
type CVEDetails struct {
	ID          string    // CVE ID (e.g., CVE-2023-1234)
	Description string    // Description of the vulnerability
	Severity    string    // CVSS severity (Critical, High, Medium, Low)
	Score       float64   // CVSS score
	Published   time.Time // When the CVE was published
	FixedIn     string    // Version where this CVE was fixed
}

// CVEInfo holds CVE information for a package version range
type CVEInfo struct {
	Current []CVEDetails // CVEs affecting the current version
	Fixed   []CVEDetails // CVEs that would be fixed by upgrading
	New     []CVEDetails // New CVEs introduced in versions between current and latest
}

// fetchCVEs fetches CVE information for a given package and version range
func fetchCVEs(pkgName string, currentVersion, latestVersion string) (*CVEInfo, error) {
	// For now, we'll use the OSV database API (https://osv.dev/docs/)
	// In a production environment, you might want to use multiple sources
	url := fmt.Sprintf("https://api.osv.dev/v1/query")

	query := map[string]interface{}{
		"package": map[string]string{
			"name":    pkgName,
			"ecosystem": "npm",
		},
	}

	jsonData, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query: %v", err)
	}

	resp, err := http.Post(url, "application/json", strings.NewReader(string(jsonData)))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CVE data: %v", err)
	}
	defer resp.Body.Close()

	var result struct {
		Vulns []struct {
			ID string `json:"id"`
			Details string `json:"details"`
			Severity []struct {
				Type  string  `json:"type"`
				Score float64 `json:"score"`
			} `json:"severity"`
			Published time.Time `json:"published"`
			Affected []struct {
				Ranges []struct {
					Type   string `json:"type"`
					Events []struct {
						Introduced string `json:"introduced,omitempty"`
						Fixed      string `json:"fixed,omitempty"`
					} `json:"events"`
				} `json:"ranges"`
			} `json:"affected"`
		} `json:"vulns"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode CVE data: %v", err)
	}

	info := &CVEInfo{}
	
	// Process each vulnerability
	for _, vuln := range result.Vulns {
		severity := "Unknown"
		score := 0.0
		
		if len(vuln.Severity) > 0 {
			score = vuln.Severity[0].Score
			switch {
			case score >= 9.0:
				severity = "Critical"
			case score >= 7.0:
				severity = "High"
			case score >= 4.0:
				severity = "Medium"
			default:
				severity = "Low"
			}
		}

		details := CVEDetails{
			ID:          vuln.ID,
			Description: vuln.Details,
			Severity:    severity,
			Score:       score,
			Published:   vuln.Published,
		}

		// Determine if this CVE affects the current version and/or is fixed in a later version
		for _, affected := range vuln.Affected {
			for _, r := range affected.Ranges {
				for _, event := range r.Events {
					if event.Fixed != "" {
						details.FixedIn = event.Fixed
						if isVersionInRange(currentVersion, event.Introduced, event.Fixed) {
							info.Current = append(info.Current, details)
						} else if isVersionInRange(latestVersion, event.Introduced, event.Fixed) {
							info.New = append(info.New, details)
						}
					}
				}
			}
		}
	}

	return info, nil
}

// isVersionInRange checks if a version is within a given range
func isVersionInRange(version, introduced, fixed string) bool {
	// This is a simplified version. In production, you'd want to use proper semver comparison
	return version >= introduced && (fixed == "" || version < fixed)
} 