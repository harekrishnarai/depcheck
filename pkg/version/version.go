package version

import (
	"fmt"
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

// AnalyzePackage checks a package version and returns analysis results
func AnalyzePackage(pkgName, pkgVersion string) (*PackageAnalysis, error) {
	// For now, we'll return a mock analysis
	// In a real implementation, this would fetch actual package data
	// from npm registry or other sources
	current, err := semver.NewVersion(pkgVersion)
	if err != nil {
		return nil, fmt.Errorf("invalid version format: %v", err)
	}

	// Mock data - in real implementation, this would come from package registry
	latest := "4.18.2"
	patched := "4.18.2"
	hasBreakingChanges := false
	securityImplications := "No known security issues"
	recommendation := "Version is up to date"

	// Compare versions
	latestVer, err := semver.NewVersion(latest)
	if err == nil {
		if current.LessThan(latestVer) {
			recommendation = fmt.Sprintf("Consider upgrading to %s", latest)
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