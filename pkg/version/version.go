package version

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// PackageAnalysis represents the analysis result for a single package
type PackageAnalysis struct {
	Name              string    // Package name
	Current           string    // Current version
	Latest            string    // Latest version available
	Patched           string    // Latest patched version in current major
	HasBreakingChanges bool     // Whether upgrading would introduce breaking changes
	CVEs              *CVEInfo  // Vulnerability information
	DependencyPath    string    // Path of dependency in the dependency tree
	IsTransitive      bool      // Whether this is a transitive dependency
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

// NpmPackageLock represents the structure of a package-lock.json file
type NpmPackageLock struct {
	Dependencies map[string]struct {
		Version      string                 `json:"version"`
		Resolved     string                 `json:"resolved,omitempty"`
		Requires     map[string]string      `json:"requires,omitempty"`
		Dependencies interface{}            `json:"dependencies,omitempty"`
	} `json:"dependencies"`
	Packages map[string]struct {
		Version  string `json:"version"`
		Resolved string `json:"resolved,omitempty"`
	} `json:"packages,omitempty"` // For newer package-lock format (npm 7+)
}

// YarnLockEntry represents an entry in a yarn.lock file
type YarnLockEntry struct {
	Version string
	Dependencies map[string]string
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

// AnalyzeNpmLockFile analyzes package-lock.json or npm-shrinkwrap.json and returns version information
func AnalyzeNpmLockFile(file io.Reader) ([]PackageAnalysis, error) {
	var lockFile NpmPackageLock

	if err := json.NewDecoder(file).Decode(&lockFile); err != nil {
		return nil, fmt.Errorf("failed to parse npm lock file: %v", err)
	}

	var analyses []PackageAnalysis
	processed := make(map[string]bool) // Track already processed packages to avoid duplicates

	// First check newer format (npm 7+)
	if len(lockFile.Packages) > 0 {
		fmt.Printf("📦 Analyzing lockfile (including transitive dependencies)...\n")
		
		// First, identify direct dependencies to build the dependency tree
		directDeps := make(map[string]bool)
		for pkgPath := range lockFile.Packages {
			// Direct dependencies are typically at node_modules/package or node_modules/@scope/package
			parts := strings.Split(pkgPath, "/")
			if len(parts) < 2 || parts[0] != "node_modules" {
				continue
			}
			
			// Regular package as direct dependency
			if len(parts) == 2 && !strings.HasPrefix(parts[1], "@") {
				directDeps[parts[1]] = true
			// Scoped package as direct dependency
			} else if len(parts) == 3 && strings.HasPrefix(parts[1], "@") {
				directDeps[parts[1]+"/"+parts[2]] = true
			}
		}
		
		// Now process all packages, marking them as direct or transitive
		for pkgPath, pkg := range lockFile.Packages {
			// Skip the root package
			if pkgPath == "" || pkgPath == "." {
				continue
			}
			
			// Skip node_modules prefix in path if it exists
			if strings.HasPrefix(pkgPath, "node_modules/") {
				pkgPath = strings.TrimPrefix(pkgPath, "node_modules/")
			}
			
			// Parse package name
			parts := strings.Split(pkgPath, "/")
			if len(parts) == 0 {
				continue
			}
			
			var pkgName string
			var isTransitive bool
			var depPath string
			
			// Handle different package path formats
			if len(parts) == 1 {
				// Direct dependency without node_modules prefix
				pkgName = parts[0]
				isTransitive = false
			} else if len(parts) == 2 && strings.HasPrefix(parts[0], "@") {
				// Scoped package as direct dependency without node_modules prefix
				pkgName = parts[0] + "/" + parts[1]
				isTransitive = false
			} else {
				// This is likely a transitive dependency
				// Extract the actual package name from the path
				if len(parts) >= 2 && strings.HasPrefix(parts[len(parts)-2], "@") {
					// Scoped package at the end of a path (transitive)
					pkgName = parts[len(parts)-2] + "/" + parts[len(parts)-1]
				} else {
					// Regular package at the end of a path (transitive)
					pkgName = parts[len(parts)-1]
				}
				
				// Mark as transitive and build dependency path
				isTransitive = true
				depPath = buildDependencyPath(pkgPath)
			}
			
			// Skip if we've already processed this package version
			if pkgName == "" || processed[pkgName+"@"+pkg.Version] {
				continue
			}
			
			// Also check if this is a direct dep based on our earlier scan
			if directDeps[pkgName] {
				isTransitive = false
			}
			
			// Mark as processed
			processed[pkgName+"@"+pkg.Version] = true
			
			// Analyze the dependency
			if analysis, err := analyzeDependency(pkgName, pkg.Version); err == nil {
				// Add additional info for transitive deps
				analysis.IsTransitive = isTransitive
				if isTransitive {
					analysis.DependencyPath = depPath
				}
				analyses = append(analyses, analysis)
			} else {
				fmt.Printf("Warning: failed to analyze %s: %v\n", pkgName, err)
			}
		}
	} else {
		// Use older format (npm 5-6)
		fmt.Printf("📦 Analyzing lockfile (older format)...\n")
		analyzeNpmLockDependencies(lockFile.Dependencies, "", &analyses, processed)
	}

	return analyses, nil
}

// buildDependencyPath creates a readable dependency path from a node_modules path
func buildDependencyPath(pkgPath string) string {
	parts := strings.Split(pkgPath, "/")
	if len(parts) <= 2 {
		return pkgPath
	}
	
	// Build a path like "express → connect → qs"
	var result []string
	for i := 0; i < len(parts); i++ {
		if parts[i] == "node_modules" {
			continue
		}
		
		// Handle scoped packages
		if strings.HasPrefix(parts[i], "@") && i+1 < len(parts) {
			result = append(result, parts[i]+"/"+parts[i+1])
			i++ // Skip the next part as it's part of the scoped package
		} else {
			result = append(result, parts[i])
		}
	}
	
	return strings.Join(result, " → ")
}

// analyzeNpmLockDependencies recursively analyzes dependencies in older npm lock format
func analyzeNpmLockDependencies(deps map[string]struct {
	Version  string `json:"version"`
	Resolved string `json:"resolved,omitempty"`
	Requires map[string]string `json:"requires,omitempty"`
	Dependencies interface{} `json:"dependencies,omitempty"`
}, path string, analyses *[]PackageAnalysis, processed map[string]bool) {
	for name, pkg := range deps {
		// Skip if we've already processed this package
		if processed[name+"@"+pkg.Version] {
			continue
		}
		
		// Mark as processed
		processed[name+"@"+pkg.Version] = true
		
		// Determine if it's a transitive dependency
		isTransitive := path != ""
		
		// Create dependency path
		depPath := name
		if path != "" {
			depPath = path + " → " + name
		}
		
		// Analyze the dependency
		if analysis, err := analyzeDependency(name, pkg.Version); err == nil {
			if isTransitive {
				analysis.DependencyPath = depPath
				analysis.IsTransitive = true
			}
			*analyses = append(*analyses, analysis)
		} else {
			fmt.Printf("Warning: failed to analyze %s: %v\n", name, err)
		}
		
		// Recursively analyze nested dependencies if they exist
		if pkg.Dependencies != nil {
			// Since lock file formats can vary, use a type assertion to process nested deps
			if nestedDeps, ok := pkg.Dependencies.(map[string]interface{}); ok {
				// Convert to the format we need
				convertedDeps := make(map[string]struct {
					Version  string `json:"version"`
					Resolved string `json:"resolved,omitempty"`
					Requires map[string]string `json:"requires,omitempty"`
					Dependencies interface{} `json:"dependencies,omitempty"`
				})
				
				for nestedName, nestedPkg := range nestedDeps {
					if nestedPkgMap, ok := nestedPkg.(map[string]interface{}); ok {
						var converted struct {
							Version  string `json:"version"`
							Resolved string `json:"resolved,omitempty"`
							Requires map[string]string `json:"requires,omitempty"`
							Dependencies interface{} `json:"dependencies,omitempty"`
						}
						
						// Extract version
						if ver, ok := nestedPkgMap["version"].(string); ok {
							converted.Version = ver
						}
						
						// Extract resolved
						if res, ok := nestedPkgMap["resolved"].(string); ok {
							converted.Resolved = res
						}
						
						// Extract requires
						if req, ok := nestedPkgMap["requires"].(map[string]interface{}); ok {
							converted.Requires = make(map[string]string)
							for k, v := range req {
								if vStr, ok := v.(string); ok {
									converted.Requires[k] = vStr
								}
							}
						}
						
						// Extract nested dependencies
						if deps, ok := nestedPkgMap["dependencies"]; ok {
							converted.Dependencies = deps
						}
						
						convertedDeps[nestedName] = converted
					}
				}
				
				analyzeNpmLockDependencies(convertedDeps, depPath, analyses, processed)
			}
		}
	}
}

// AnalyzeYarnLockFile analyzes a yarn.lock file and returns version information
func AnalyzeYarnLockFile(file io.Reader) ([]PackageAnalysis, error) {
	// Read all lines
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read yarn.lock: %v", err)
	}

	// Parse the file content
	content := string(data)
	lines := strings.Split(content, "\n")

	// Map to store package name and resolved version
	packages := make(map[string]string)
	
	var currentPackage string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		// This line defines a package
		if strings.Contains(line, ":") && !strings.HasPrefix(line, " ") {
			// Get the package name and clean it
			pkgLine := strings.Split(line, ":")[0]
			pkgLine = strings.Trim(pkgLine, "\"'")
			
			// Extract the package name from the line (yarn uses "pkg@version" format)
			parts := strings.Split(pkgLine, "@")
			if len(parts) >= 2 {
				// Handle scoped packages (@scope/package)
				if strings.HasPrefix(parts[0], "@") {
					if len(parts) >= 3 {
						currentPackage = parts[0] + "@" + parts[1]
					}
				} else {
					currentPackage = parts[0]
				}
			}
		}
		
		// This line contains the version
		if strings.HasPrefix(line, "  version ") && currentPackage != "" {
			parts := strings.Split(line, "\"")
			if len(parts) >= 2 {
				version := strings.Trim(parts[1], "\"")
				packages[currentPackage] = version
			}
		}
	}

	// Create analyses from parsed packages
	var analyses []PackageAnalysis
	for name, version := range packages {
		if analysis, err := analyzeDependency(name, version); err == nil {
			analyses = append(analyses, analysis)
		} else {
			fmt.Printf("Warning: failed to analyze %s: %v\n", name, err)
		}
	}

	return analyses, nil
}

// FindAndAnalyzeLockFile looks for a lock file based on the package file path and analyzes it
func FindAndAnalyzeLockFile(packageFilePath string) ([]PackageAnalysis, error) {
	// Determine the directory of the package file
	dir := packageFilePath[:strings.LastIndex(packageFilePath, "/")+1]
	if dir == "" {
		dir = "./"
	}
	
	// Try to find npm package-lock.json (most common)
	lockPath := dir + "package-lock.json"
	if file, err := os.Open(lockPath); err == nil {
		defer file.Close()
		fmt.Printf("📦 Found package-lock.json, using exact versions from lock file...\n")
		return AnalyzeNpmLockFile(file)
	}
	
	// Try to find yarn.lock
	lockPath = dir + "yarn.lock"
	if file, err := os.Open(lockPath); err == nil {
		defer file.Close()
		fmt.Printf("📦 Found yarn.lock, using exact versions from lock file...\n")
		return AnalyzeYarnLockFile(file)
	}
	
	// Try to find npm-shrinkwrap.json
	lockPath = dir + "npm-shrinkwrap.json"
	if file, err := os.Open(lockPath); err == nil {
		defer file.Close()
		fmt.Printf("📦 Found npm-shrinkwrap.json, using exact versions from lock file...\n")
		return AnalyzeNpmLockFile(file)
	}
	
	// No lock file found, return error
	return nil, fmt.Errorf("no lock file found")
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