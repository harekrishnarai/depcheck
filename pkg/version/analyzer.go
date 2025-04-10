package version

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Masterminds/semver/v3"
)

type PackageInfo struct {
	Name    string
	Current string
	Latest  string
	Patched string
}

type VersionAnalysis struct {
	PackageInfo
	HasBreakingChanges bool
	SecurityImplications string
	Recommendation      string
}

type NpmPackage struct {
	Versions map[string]struct {
		Deprecated string `json:"deprecated"`
	} `json:"versions"`
	DistTags struct {
		Latest string `json:"latest"`
	} `json:"dist-tags"`
}

func AnalyzePackage(name, version string) (*VersionAnalysis, error) {
	// Fetch package information from npm registry
	resp, err := http.Get(fmt.Sprintf("https://registry.npmjs.org/%s", name))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch package info: %v", err)
	}
	defer resp.Body.Close()

	var pkg NpmPackage
	if err := json.NewDecoder(resp.Body).Decode(&pkg); err != nil {
		return nil, fmt.Errorf("failed to decode package info: %v", err)
	}

	analysis := &VersionAnalysis{
		PackageInfo: PackageInfo{
			Name:    name,
			Current: version,
			Latest:  pkg.DistTags.Latest,
		},
	}

	// Parse versions
	current, err := semver.NewVersion(version)
	if err != nil {
		return nil, fmt.Errorf("invalid current version: %v", err)
	}

	latest, err := semver.NewVersion(pkg.DistTags.Latest)
	if err != nil {
		return nil, fmt.Errorf("invalid latest version: %v", err)
	}

	// Check for major version changes
	if latest.Major() > current.Major() {
		analysis.HasBreakingChanges = true
		analysis.SecurityImplications = "Major version upgrade may include breaking changes and security improvements"
		analysis.Recommendation = "Review changelog and test thoroughly before upgrading"
	} else if latest.Minor() > current.Minor() {
		analysis.SecurityImplications = "Minor version upgrade may include new features and security patches"
		analysis.Recommendation = "Consider upgrading after testing"
	} else if latest.Patch() > current.Patch() {
		analysis.SecurityImplications = "Patch version upgrade likely includes security fixes"
		analysis.Recommendation = "Recommended to upgrade"
	}

	// Find the latest patched version in the current major version
	for v := range pkg.Versions {
		ver, err := semver.NewVersion(v)
		if err != nil {
			continue
		}
		if ver.Major() == current.Major() && ver.GreaterThan(current) {
			if analysis.Patched == "" || ver.GreaterThan(semver.MustParse(analysis.Patched)) {
				analysis.Patched = v
			}
		}
	}

	return analysis, nil
}

func AnalyzePackageFile(reader io.Reader) ([]VersionAnalysis, error) {
	var pkgJson struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}

	if err := json.NewDecoder(reader).Decode(&pkgJson); err != nil {
		return nil, fmt.Errorf("failed to parse package.json: %v", err)
	}

	var analyses []VersionAnalysis
	for name, version := range pkgJson.Dependencies {
		// Remove ^ or ~ from version string
		cleanVersion := strings.TrimLeft(version, "^~")
		analysis, err := AnalyzePackage(name, cleanVersion)
		if err != nil {
			return nil, fmt.Errorf("failed to analyze package %s: %v", name, err)
		}
		analyses = append(analyses, *analysis)
	}

	return analyses, nil
} 