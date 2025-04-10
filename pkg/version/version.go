package version

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// PackageAnalysis represents the analysis result for a single package
type PackageAnalysis struct {
	Name              string    // Package name
	Current          string    // Current version
	Latest           string    // Latest version available
	Patched          string    // Latest patched version in current major
	HasBreakingChanges bool    // Whether upgrading would introduce breaking changes
	CVEs             *CVEInfo  // Vulnerability information
}

// NpmPackage represents the structure of an npm package from the registry
type NpmPackage struct {
	Versions map[string]struct {
		Deprecated string `json:"deprecated"`
	} `json:"versions"`
	DistTags struct {
		Latest string `json:"latest"`
	} `json:"dist-tags"`
}

// AnalyzePackage checks a package version and returns analysis results
func AnalyzePackage(pkgName, pkgVersion string) (*PackageAnalysis, error) {
	// Fetch package information from npm registry
	resp, err := http.Get(fmt.Sprintf("https://registry.npmjs.org/%s", pkgName))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch package info: %v", err)
	}
	defer resp.Body.Close()

	var pkg NpmPackage
	if err := json.NewDecoder(resp.Body).Decode(&pkg); err != nil {
		return nil, fmt.Errorf("failed to decode package info: %v", err)
	}

	current, err := semver.NewVersion(pkgVersion)
	if err != nil {
		return nil, fmt.Errorf("invalid version format: %v", err)
	}

	latest := pkg.DistTags.Latest
	latestVer, err := semver.NewVersion(latest)
	if err != nil {
		return nil, fmt.Errorf("invalid latest version format: %v", err)
	}

	// Find the latest patched version in the current major version
	patched := pkgVersion
	for v := range pkg.Versions {
		ver, err := semver.NewVersion(v)
		if err != nil {
			continue
		}
		if ver.Major() == current.Major() && ver.GreaterThan(current) {
			if patched == pkgVersion || ver.GreaterThan(semver.MustParse(patched)) {
				patched = v
			}
		}
	}

	hasBreakingChanges := latestVer.Major() > current.Major()

	// Fetch CVE information
	cveInfo, err := fetchCVEs(pkgName, pkgVersion, latest)
	if err != nil {
		// Log the error but don't fail the analysis
		fmt.Printf("Warning: Failed to fetch CVE data: %v\n", err)
	}

	return &PackageAnalysis{
		Name:                pkgName,
		Current:            pkgVersion,
		Latest:             latest,
		Patched:            patched,
		HasBreakingChanges: hasBreakingChanges,
		CVEs:               cveInfo,
	}, nil
}

// AnalyzePackageFile analyzes a package file (e.g., package.json) and returns version information
func AnalyzePackageFile(file io.Reader) ([]PackageAnalysis, error) {
	var pkgJSON struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}

	if err := json.NewDecoder(file).Decode(&pkgJSON); err != nil {
		return nil, fmt.Errorf("failed to parse package.json: %v", err)
	}

	var analyses []PackageAnalysis

	// Process dependencies
	for name, version := range pkgJSON.Dependencies {
		analysis, err := analyzeDependency(name, version)
		if err != nil {
			fmt.Printf("Warning: failed to analyze %s: %v\n", name, err)
			continue
		}
		analyses = append(analyses, analysis)
	}

	// Process devDependencies
	for name, version := range pkgJSON.DevDependencies {
		analysis, err := analyzeDependency(name, version)
		if err != nil {
			fmt.Printf("Warning: failed to analyze %s: %v\n", name, err)
			continue
		}
		analyses = append(analyses, analysis)
	}

	return analyses, nil
}

// getLatestVersion fetches the latest version of a package from the npm registry
func getLatestVersion(pkgName string) (string, error) {
	resp, err := http.Get(fmt.Sprintf("https://registry.npmjs.org/%s", pkgName))
	if err != nil {
		return "", fmt.Errorf("failed to fetch package info: %v", err)
	}
	defer resp.Body.Close()

	var pkg NpmPackage
	if err := json.NewDecoder(resp.Body).Decode(&pkg); err != nil {
		return "", fmt.Errorf("failed to decode package info: %v", err)
	}

	return pkg.DistTags.Latest, nil
}

// analyzeDependency analyzes a single dependency and returns its analysis result
func analyzeDependency(name, version string) (PackageAnalysis, error) {
	// Clean up version string
	version = strings.TrimPrefix(version, "^")
	version = strings.TrimPrefix(version, "~")

	// Get latest version from npm registry
	latest, err := getLatestVersion(name)
	if err != nil {
		return PackageAnalysis{}, fmt.Errorf("failed to get latest version: %v", err)
	}

	// Get patched version (highest version in current major)
	currentVer, err := semver.NewVersion(version)
	if err != nil {
		return PackageAnalysis{}, fmt.Errorf("failed to parse current version: %v", err)
	}

	latestVer, err := semver.NewVersion(latest)
	if err != nil {
		return PackageAnalysis{}, fmt.Errorf("failed to parse latest version: %v", err)
	}

	// Get patched version (highest version in current major)
	patched := latest
	if currentVer.Major() != latestVer.Major() {
		// Find highest version in current major
		patched = fmt.Sprintf("%d.%d.%d", currentVer.Major(), latestVer.Minor(), latestVer.Patch())
	}

	// Check for breaking changes
	hasBreakingChanges := currentVer.Major() != latestVer.Major()

	// Get CVE information
	cves, err := fetchCVEs(name, version, latest)
	if err != nil {
		fmt.Printf("Warning: failed to fetch CVE data: %v\n", err)
		cves = &CVEInfo{} // Use empty CVE info if fetch fails
	}

	return PackageAnalysis{
		Name:              name,
		Current:          version,
		Latest:           latest,
		Patched:          patched,
		HasBreakingChanges: hasBreakingChanges,
		CVEs:             cves,
	}, nil
}

// CompareVersions compares two semantic versions and returns:
// -1 if v1 < v2
// 0 if v1 == v2
// 1 if v1 > v2
func CompareVersions(v1, v2 string) int {
	// Remove any leading 'v' or 'V' from versions
	v1 = strings.TrimLeft(v1, "vV")
	v2 = strings.TrimLeft(v2, "vV")

	// Split versions into parts
	v1Parts := strings.Split(v1, ".")
	v2Parts := strings.Split(v2, ".")

	// Compare each part
	for i := 0; i < max(len(v1Parts), len(v2Parts)); i++ {
		var v1Part, v2Part string
		if i < len(v1Parts) {
			v1Part = v1Parts[i]
		}
		if i < len(v2Parts) {
			v2Part = v2Parts[i]
		}

		// Convert parts to integers
		v1Num, err1 := strconv.Atoi(v1Part)
		v2Num, err2 := strconv.Atoi(v2Part)

		// If either part is not a number, compare as strings
		if err1 != nil || err2 != nil {
			if v1Part < v2Part {
				return -1
			}
			if v1Part > v2Part {
				return 1
			}
			continue
		}

		// Compare numeric parts
		if v1Num < v2Num {
			return -1
		}
		if v1Num > v2Num {
			return 1
		}
	}

	return 0
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
} 