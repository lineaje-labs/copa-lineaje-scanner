package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	v1alpha1 "github.com/project-copacetic/copacetic/pkg/types/v1alpha1"
)

type LineajeParser struct{}

func parseLineajeReport(file string) (*LineajeReport, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	var lineaje LineajeReport
	if err = json.Unmarshal(data, &lineaje); err != nil {
		return nil, err
	}
	return &lineaje, nil
}

func newLineajeParser() *LineajeParser {
	return &LineajeParser{}
}

func (k *LineajeParser) parse(file string) (*v1alpha1.UpdateManifest, error) {

	report, err := parseLineajeReport(file)
	if err != nil {
		return nil, err
	}

	updates := v1alpha1.UpdateManifest{
		APIVersion: v1alpha1.APIVersion,
	}

	for i := range report.Meta_data.Comprehensive_plan_components {
		vulnerabilities := &report.Meta_data.Comprehensive_plan_components[i]
		if vulnerabilities.Target_component_purl != "" && strings.Contains(vulnerabilities.Current_component_purl, "distro") {
			pkgURL := vulnerabilities.Current_component_purl
			u, err := url.Parse(pkgURL)
			if err != nil {
				fmt.Println("Error parsing URL:", err)
			}
			queryParams := u.Query()
			distroValue := queryParams.Get("distro")
			archValue := queryParams.Get("arch")
			distroParts := strings.Split(distroValue, "-")
			osType := getOsType(distroParts[0])
			updates.Metadata = v1alpha1.Metadata{
				OS: v1alpha1.OS{
					Type:    osType,
					Version: distroParts[1],
				},
				Config: v1alpha1.Config{
					Arch: archValue,
				},
			}
			decodedStr, err := url.QueryUnescape(getPackageVersion(vulnerabilities.Current_component_purl))
			if err != nil {
				fmt.Println("Error decoding string:", err)
				decodedStr = getPackageVersion(vulnerabilities.Current_component_purl)
			}
			if len(strings.TrimSpace(vulnerabilities.Current_component_purl)) != 0 && len(strings.TrimSpace(vulnerabilities.Target_component_purl)) != 0 {
				updates.Updates = append(updates.Updates, v1alpha1.UpdatePackage{
					Name:             getPackageName(vulnerabilities.Current_component_purl),
					InstalledVersion: decodedStr,
					FixedVersion:     getPackageVersion(vulnerabilities.Target_component_purl),
					VulnerabilityID:  vulnerabilities.Vulnerability_id,
				})
			}
		}
	}

	for i := range report.Meta_data.Balanced_plan_components_vulnerability_fixes {
		vulnerabilities := &report.Meta_data.Balanced_plan_components_vulnerability_fixes[i]
		if vulnerabilities.Target_component_purl != "" && strings.Contains(vulnerabilities.Current_component_purl, "distro") {
			pkgURL := vulnerabilities.Current_component_purl
			u, err := url.Parse(pkgURL)
			if err != nil {
				fmt.Println("Error parsing URL:", err)
			}
			queryParams := u.Query()
			distroValue := queryParams.Get("distro")
			archValue := queryParams.Get("arch")
			distroParts := strings.Split(distroValue, "-")
			osType := getOsType(distroParts[0])
			updates.Metadata = v1alpha1.Metadata{
				OS: v1alpha1.OS{
					Type:    osType,
					Version: distroParts[1],
				},
				Config: v1alpha1.Config{
					Arch: archValue,
				},
			}
			decodedStr, err := url.QueryUnescape(getPackageVersion(vulnerabilities.Current_component_purl))
			if err != nil {
				fmt.Println("Error decoding string:", err)
				decodedStr = getPackageVersion(vulnerabilities.Current_component_purl)
			}
			if len(strings.TrimSpace(vulnerabilities.Current_component_purl)) != 0 && len(strings.TrimSpace(vulnerabilities.Target_component_purl)) != 0 {
				var name string = getPackageName(vulnerabilities.Current_component_purl)
				if !checkComponentExist(updates.Updates, name) {
					updates.Updates = append(updates.Updates, v1alpha1.UpdatePackage{
						Name:             name,
						InstalledVersion: decodedStr,
						FixedVersion:     getPackageVersion(vulnerabilities.Target_component_purl),
						VulnerabilityID:  vulnerabilities.Vulnerability_id,
					})
				}

			}
		}
	}

	for i := range report.Meta_data.Basic_plan_component_vulnerability_fixes {
		vulnerabilities := &report.Meta_data.Basic_plan_component_vulnerability_fixes[i]
		if vulnerabilities.Target_component_purl != "" && strings.Contains(vulnerabilities.Current_component_purl, "distro") {
			pkgURL := vulnerabilities.Current_component_purl
			u, err := url.Parse(pkgURL)
			if err != nil {
				fmt.Println("Error parsing URL:", err)
			}
			queryParams := u.Query()
			distroValue := queryParams.Get("distro")
			archValue := queryParams.Get("arch")
			distroParts := strings.Split(distroValue, "-")
			osType := getOsType(distroParts[0])
			updates.Metadata = v1alpha1.Metadata{
				OS: v1alpha1.OS{
					Type:    osType,
					Version: distroParts[1],
				},
				Config: v1alpha1.Config{
					Arch: archValue,
				},
			}
			decodedStr, err := url.QueryUnescape(getPackageVersion(vulnerabilities.Current_component_purl))
			if err != nil {
				fmt.Println("Error decoding string:", err)
				decodedStr = getPackageVersion(vulnerabilities.Current_component_purl)
			}
			if len(strings.TrimSpace(vulnerabilities.Current_component_purl)) != 0 && len(strings.TrimSpace(vulnerabilities.Target_component_purl)) != 0 {
				var name string = getPackageName(vulnerabilities.Current_component_purl)
				if !checkComponentExist(updates.Updates, name) {
					updates.Updates = append(updates.Updates, v1alpha1.UpdatePackage{
						Name:             getPackageName(vulnerabilities.Current_component_purl),
						InstalledVersion: decodedStr,
						FixedVersion:     getPackageVersion(vulnerabilities.Target_component_purl),
						VulnerabilityID:  vulnerabilities.Vulnerability_id,
					})

				}
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
	lineajeParser := newLineajeParser()

	// Get the image report from command line
	imageReport := os.Args[1]
	report, err := lineajeParser.parse(imageReport)
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

func getPackageVersion(packageString string) string {
	parts := strings.Split(packageString, "@")
	if len(parts) > 1 {
		version := strings.Split(parts[1], "?")[0]
		return version
	}
	return ""
}
func getPackageName(packageString string) string {
	parts := strings.Split(packageString, "@")
	if len(parts) > 1 {
		name := strings.Split(parts[0], "?")[0]
		baseName := filepath.Base(name)
		return baseName
	}
	return ""
}

func getOsType(osType string) string {
	if osType == "amzn" {
		return "amazon"
	}
	return osType
}

func checkComponentExist(updatePackages v1alpha1.UpdatePackages, name string) bool {
	for i := range updatePackages {
		if updatePackages[i].Name == name {
			return true
		}
	}
	return false
}