package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	v1alpha1 "github.com/project-copacetic/copacetic/pkg/types/v1alpha1"
	"github.com/package-url/packageurl-go"
)

type LinajeParser struct{}

// parseLineajeReport parses a fake report from a file
func parseLineajeReport(file string) (*LineajeReport, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	var fake LineajeReport
	if err = json.Unmarshal(data, &fake); err != nil {
		return nil, err
	}

	return &fake, nil
}

func newLinajeParser() *LinajeParser {
	return &LinajeParser{}
}

func extractDistro(qualifiers packageurl.Qualifiers) string {
	distro, ok := qualifiers.Map()["distro"]
	if !ok || distro == "" {
		return ""
	}
	parts := strings.SplitN(distro, "-", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return distro
}

func (k *LinajeParser) parse(file string) (*v1alpha1.UpdateManifest, error) {
	// Parse the fake report
	report, err := parseLineajeReport(file)
	if err != nil {
		return nil, err
	}

	// Create the standardized report
	updates := v1alpha1.UpdateManifest{
		APIVersion: v1alpha1.APIVersion,
		Metadata: v1alpha1.Metadata{
			OS: v1alpha1.OS{
				Type: report.OSType,
				Version: report.OSVersion,
			},
			Config: v1alpha1.Config{
				Arch: report.Arch,
			},
		},
	}

	osPurlTypes := map[string]struct{}{
		"alpm":   {},
		"apk":    {},
		"deb":    {},
		"rpm":    {},
		"nix":    {},
		"oci":    {},
		"docker": {},
		"qpkg":   {},
	}

	// Convert the fake report to the standardized report
	var setOSDetails = false
	for i := range report.Metadata.Basic_plan_component_vulnerability_fixes {
		pkgs := &report.Metadata.Basic_plan_component_vulnerability_fixes[i]
		if pkgs.Current_component_purl != "" && pkgs.Target_component_purl != "" {
			installedInstance, err := packageurl.FromString(pkgs.Current_component_purl)
			if err != nil {
				return nil, err
			}
			_, exists := osPurlTypes[strings.ToLower(installedInstance.Type)]
			if exists {
				if !setOSDetails {
					setOSDetails = true
					updates.Metadata.OS.Type = installedInstance.Namespace
					updates.Metadata.OS.Version = extractDistro(installedInstance.Qualifiers)
					updates.Metadata.Config.Arch = installedInstance.Qualifiers.Map()["arch"]
				}
				targetInstance, err := packageurl.FromString(pkgs.Target_component_purl)
				if err != nil {
					return nil, err
				}
				updates.Updates = append(updates.Updates, v1alpha1.UpdatePackage{
					Name: targetInstance.Name,
					InstalledVersion: installedInstance.Version,
					FixedVersion: targetInstance.Version,
					VulnerabilityID: pkgs.Vulnerability_id,
				})
			}
		}
	}
	return &updates, nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <image report>\n", os.Args[0])
		os.Exit(1)
	}

	// Initialize the parser
	fakeParser := newLinajeParser()

	// Get the image report from command line
	imageReport := os.Args[1]

	report, err := fakeParser.parse(imageReport)
	if err != nil {
		fmt.Printf("error parsing report: %v\n", err)
		os.Exit(1)
	}

	// Serialize the standardized report and print it to stdout
	reportBytes, err := json.Marshal(report)
	if err != nil {
		fmt.Printf("Error serializing report: %v\n", err)
		os.Exit(1)
	}

	os.Stdout.Write(reportBytes)
}