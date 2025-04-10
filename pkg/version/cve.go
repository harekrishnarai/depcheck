package version

import (
	"encoding/json"
	"fmt"
	"net/http"
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
}

// CVEInfo holds CVE information for a package version range
type CVEInfo struct {
	Current []CVEDetails // CVEs affecting the current version
	Fixed   []CVEDetails // CVEs that would be fixed by upgrading
	New     []CVEDetails // New CVEs introduced in versions between current and latest
}

// OSVResponse represents the response from OSV API
type OSVResponse struct {
	Vulns []struct {
		ID        string    `json:"id"`
		Details   string    `json:"details"`
		Severity  []struct {
			Type  string      `json:"type"`
			Score interface{} `json:"score"` // Can be string or float64
		} `json:"severity"`
		Modified  time.Time `json:"modified"`
		Published time.Time `json:"published"`
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
			DatabaseSpecific struct {
				Severity string `json:"severity"`
			} `json:"database_specific"`
		} `json:"affected"`
	} `json:"vulns"`
}

// fetchCVEs fetches CVE information for a given package and version range
func fetchCVEs(pkgName string, currentVersion, latestVersion string) (*CVEInfo, error) {
	url := fmt.Sprintf("https://api.osv.dev/v1/query")

	query := map[string]interface{}{
		"package": map[string]string{
			"name":      pkgName,
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

	var result OSVResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode CVE data: %v", err)
	}

	info := &CVEInfo{}
	
	// Process each vulnerability
	for _, vuln := range result.Vulns {
		severity := "Unknown"
		score := 0.0

		// Try to get severity from database_specific first
		if len(vuln.Affected) > 0 {
			severity = vuln.Affected[0].DatabaseSpecific.Severity
		}

		// If no severity found, try to determine from score
		if severity == "" && len(vuln.Severity) > 0 {
			// Handle both string and float64 score types
			switch s := vuln.Severity[0].Score.(type) {
			case float64:
				score = s
			case string:
				// Try to parse the string as float
				fmt.Sscanf(s, "%f", &score)
			}

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