package main

import (
	"encoding/json"
	"fmt"
	"os"

	v1alpha1 "github.com/project-copacetic/copacetic/pkg/types/v1alpha1"
)

type LineajeParser struct{}

// parseLineajeReport parses a Lineaje report from a file
func parseLineajeReport(file string) (*LineajeReport, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	var lineajeReport LineajeReport
	if err = json.Unmarshal(data, &lineajeReport); err != nil {
		return nil, err
	}

	return &lineajeReport, nil
}

func newLineajeParser() *LineajeParser {
	return &LineajeParser{}
}

func (k *LineajeParser) parse(file string) (*v1alpha1.UpdateManifest, error) {
	// Parse the Lineaje report
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

	// Convert the Lineaje report to the standardized report
	for i := range report.Packages {
		pkgs := &report.Packages[i]
		if pkgs.FixedVersion != "" {
			updates.Updates = append(updates.Updates, v1alpha1.UpdatePackage{
				Name: pkgs.Name,
				InstalledVersion: pkgs.InstalledVersion,
				FixedVersion: pkgs.FixedVersion,
				VulnerabilityID: pkgs.VulnerabilityID,
			})
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
	lineajeReportParser := newLineajeParser()

	// Get the image report from command line
	imageReport := os.Args[1]

	report, err := lineajeReportParser.parse(imageReport)
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
