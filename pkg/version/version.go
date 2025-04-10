package version

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// PackageAnalysis represents the analysis results for a package
type PackageAnalysis struct {
	Name                string
	Current            string
	Latest             string
	Patched            string
	HasBreakingChanges bool
	SecurityImplications string
	Recommendation     string
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
	securityImplications := "No known security issues"
	recommendation := "Version is up to date"

	if latestVer.GreaterThan(current) {
		if hasBreakingChanges {
			securityImplications = "Major version upgrade may include breaking changes and security improvements"
			recommendation = "Review changelog and test thoroughly before upgrading"
		} else if latestVer.Minor() > current.Minor() {
			securityImplications = "Minor version upgrade may include new features and security patches"
			recommendation = "Consider upgrading after testing"
		} else if latestVer.Patch() > current.Patch() {
			securityImplications = "Patch version upgrade likely includes security fixes"
			recommendation = "Recommended to upgrade"
		}
	}

	return &PackageAnalysis{
		Name:                pkgName,
		Current:            pkgVersion,
		Latest:             latest,
		Patched:            patched,
		HasBreakingChanges: hasBreakingChanges,
		SecurityImplications: securityImplications,
		Recommendation:     recommendation,
	}, nil
}

// AnalyzePackageFile analyzes all dependencies in a package.json file
func AnalyzePackageFile(reader io.Reader) ([]PackageAnalysis, error) {
	var pkgJson struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}

	if err := json.NewDecoder(reader).Decode(&pkgJson); err != nil {
		return nil, fmt.Errorf("failed to parse package.json: %v", err)
	}

	var analyses []PackageAnalysis
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