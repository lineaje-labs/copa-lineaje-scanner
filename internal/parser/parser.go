package parser

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/lineaje-labs/copa-lineaje-scanner/internal/buildinfo"
	"github.com/lineaje-labs/copa-lineaje-scanner/internal/fixplan"
	"github.com/lineaje-labs/copacetic/pkg/types/v1alpha1"
	"github.com/package-url/packageurl-go"
)

var (
	// Set of OS that are known to be part of PURLs
	osPurlTypes = map[string]struct{}{
		"alpm":   {},
		"apk":    {},
		"deb":    {},
		"rpm":    {},
		"nix":    {},
		"oci":    {},
		"docker": {},
		"qpkg":   {},
	}
)

type LineajeParser struct{}

func NewLineajeParser() *LineajeParser {
	return &LineajeParser{}
}

// extractDistro extracts the distribution version from the PURL,
// For example, "18.04" from "ubuntu-18.04"
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

func (k *LineajeParser) Parse(fileName string) (*v1alpha1.UpdateManifest, error) {
	file, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Create the standardized report
	updates := v1alpha1.UpdateManifest{
		APIVersion: v1alpha1.APIVersion,
		Metadata: v1alpha1.Metadata{
			OS: v1alpha1.OS{
				Type:    "",
				Version: "",
			},
			Config: v1alpha1.Config{
				Arch: "",
			},
		},
		PluginVersion: fmt.Sprintf("%s version %s-%s", buildinfo.Name, buildinfo.Version, buildinfo.BuildNum),
	}

	decoder := json.NewDecoder(file)
	var seenMetaData, seenComponentDataList bool
	// Read tokens until we find the "meta_data" or "component_data_list" key at the root level
	var rootToken json.Token
	for {
		rootToken, err = decoder.Token()
		if err == io.EOF {
			if !seenMetaData && !seenComponentDataList {
				fmt.Println("Reached EOF without finding meta_data or component_data_list")
				return nil, fmt.Errorf("expected start of meta_data or component_data_list object")
			}
		} else if err != nil {
			return nil, err
		}

		// We are looking for a string token with the value "meta_data" of "component_data_list"
		if key, ok := rootToken.(string); (ok && key == "meta_data") || (ok && key == "component_data_list") {
			var childToken json.Token
			childToken, err = decoder.Token()
			if err != nil {
				return nil, err
			}
			switch key {
			case "meta_data":
				if delim, ok := childToken.(json.Delim); !ok || delim != '{' {
					return nil, fmt.Errorf("expected start of meta_data object")
				}
				if _, err = streamAndConvertFixes(decoder, &updates); err != nil {
					return nil, err
				}
				seenMetaData = true
			case "component_data_list":
				if delim, ok := childToken.(json.Delim); !ok || delim != '[' { // This is an array and not an object
					return nil, fmt.Errorf("expected start of component_data_list array")
				}
				if err = streamAndConvertComponentDataList(decoder, &updates); err != nil {
					return nil, err
				}
				seenComponentDataList = true
			}
		}
		if seenMetaData || seenComponentDataList {
			break
		}
	}
	return &updates, nil
}

func streamAndConvertFixes(dec *json.Decoder, updates *v1alpha1.UpdateManifest) (*v1alpha1.UpdateManifest, error) {
	setArchDetails := false

	// loop through tokens until you find "basic_plan_component_vulnerability_fixes"
	for {
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}

		// Look for the key for fixes array:
		if key, ok := t.(string); ok && key == "basic_plan_component_vulnerability_fixes" {
			// Next token must be start of an array
			t, err = dec.Token()
			if err != nil {
				return nil, err
			}
			if delim, ok := t.(json.Delim); !ok || delim != '[' {
				return nil, fmt.Errorf("expected start of array for fixes")
			}

			// decode array elements one by one
			for dec.More() {
				var fix fixplan.Report
				err := dec.Decode(&fix)
				if err != nil {
					return nil, err
				}

				// process each fix immediately
				if fix.CurrentComponentPurl != "" && fix.TargetComponentPurl != "" {
					installedInstance, err := packageurl.FromString(fix.CurrentComponentPurl)
					if err != nil {
						return nil, err
					}

					if _, exists := osPurlTypes[strings.ToLower(installedInstance.Type)]; exists {
						if !setArchDetails {
							setArchDetails = true
							updates.Metadata.Config.Arch = installedInstance.Qualifiers.Map()["arch"]
						}

						targetInstance, err := packageurl.FromString(fix.TargetComponentPurl)
						if err != nil {
							return nil, err
						}

						updates.Updates = append(updates.Updates, v1alpha1.UpdatePackage{
							Name:             targetInstance.Name,
							InstalledVersion: installedInstance.Version,
							InstalledPURL:    fix.CurrentComponentPurl,
							FixedVersion:     targetInstance.Version,
							FixedPURL:        fix.TargetComponentPurl,
							VulnerabilityID:  fix.VulnerabilityId,
						})
					}
				}
			}

			// Done processing fixes array - consume closing ']'
			t, err = dec.Token()
			if err != nil {
				return nil, err
			}
			if delim, ok := t.(json.Delim); !ok || delim != ']' {
				return nil, fmt.Errorf("expected end of array for fixes")
			}

			break // We got fixes, can stop looking further or continue parsing if needed
		}
	}

	return updates, nil
}

func streamAndConvertComponentDataList(dec *json.Decoder, updates *v1alpha1.UpdateManifest) error {
	setArchDetails := false

	for {
		// decode array elements one by one
		for dec.More() {
			var componentFixData fixplan.ComponentFixData
			err := dec.Decode(&componentFixData)
			if err != nil {
				return err
			}

			// process each fix immediately
			if componentFixData.CurrentComponentPURL != "" && componentFixData.FixedComponentPURL != "" {
				installedInstance, err := packageurl.FromString(componentFixData.CurrentComponentPURL)
				if err != nil {
					return err
				}

				if _, exists := osPurlTypes[strings.ToLower(installedInstance.Type)]; exists {
					if !setArchDetails {
						setArchDetails = true
						updates.Metadata.Config.Arch = installedInstance.Qualifiers.Map()["arch"]
					}

					targetInstance, err := packageurl.FromString(componentFixData.FixedComponentPURL)
					if err != nil {
						return err
					}

					updates.Updates = append(updates.Updates, v1alpha1.UpdatePackage{
						Name:             targetInstance.Name,
						InstalledVersion: installedInstance.Version,
						InstalledPURL:    componentFixData.CurrentComponentPURL,
						FixedVersion:     targetInstance.Version,
						FixedPURL:        componentFixData.FixedComponentPURL,
					})
				}
			}
		}
		// Process ']' which should come after component data array processing was completed
		arrayToken, err := dec.Token()
		if err != nil {
			return err
		}
		if delim, ok := arrayToken.(json.Delim); !ok || delim != ']' {
			return fmt.Errorf("expected end of array for component data")
		}
		break // All relevant data has been extracted
	}

	return nil
}
