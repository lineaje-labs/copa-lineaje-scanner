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
		ImageDetails: v1alpha1.ImageDetail{
			Platform:        "",
			ImageRepository: "",
			ImageName:       "",
			ImageVersion:    "",
			ImageDigest:     "",
			Private:         false,
		},
	}

	decoder := json.NewDecoder(file)

	var (
		seenMetaData, seenImageDetails bool
	)

	// Read tokens until we find the "meta_data" and "image_details" key at the root level
	for {
		tok, err := decoder.Token()
		if err == io.EOF {
			if !seenMetaData {
				fmt.Println("Reached EOF without finding meta_data")
				return nil, fmt.Errorf("expected start of meta_data object")
			}
			if !seenImageDetails {
				fmt.Println("Reached EOF without finding image_details")
				return nil, fmt.Errorf("expected start of image_details object")
			}
		} else if err != nil {
			return nil, err
		}

		// We are looking for a string token with the value "meta_data"
		if key, ok := tok.(string); (ok && key == "meta_data") || (ok && key == "image_details") {
			// The next token should be the start of the meta_data object
			t, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			if delim, ok := t.(json.Delim); !ok || delim != '{' {
				return nil, fmt.Errorf("expected start of meta_data object")
			}
			switch key {
			case "meta_data":
				if _, err := streamAndConvertFixes(decoder, &updates); err != nil {
					return nil, err
				}
				seenMetaData = true
			case "image_details":
				if _, err := streamAndConvertImageDetails(decoder, &updates); err != nil {
					return nil, err
				}
				seenImageDetails = true
			}
		}

		if seenMetaData && seenImageDetails {
			break
		}
	}
	return &updates, nil
}

func streamAndConvertImageDetails(dec *json.Decoder, updates *v1alpha1.UpdateManifest) (*v1alpha1.UpdateManifest, error) {
	// We are currently positioned just after the '{' that starts image_details object
	// So we need to read keys and values until we find the closing '}'
	for {
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}

		// Check if end of object
		if delim, ok := t.(json.Delim); ok && delim == '}' {
			break
		}

		// Expect key to be a string
		key, ok := t.(string)
		if !ok {
			return nil, fmt.Errorf("expected string key in image_details but got %T", t)
		}

		// Decode the value depending on key
		switch key {
		case "platform":
			if err := dec.Decode(&updates.ImageDetails.Platform); err != nil {
				return nil, err
			}
		case "image_repository":
			if err := dec.Decode(&updates.ImageDetails.ImageRepository); err != nil {
				return nil, err
			}
		case "image_name":
			if err := dec.Decode(&updates.ImageDetails.ImageName); err != nil {
				return nil, err
			}
		case "image_version":
			if err := dec.Decode(&updates.ImageDetails.ImageVersion); err != nil {
				return nil, err
			}
		case "image_digest":
			if err := dec.Decode(&updates.ImageDetails.ImageDigest); err != nil {
				return nil, err
			}
		case "private":
			if err := dec.Decode(&updates.ImageDetails.Private); err != nil {
				return nil, err
			}
		default:
			// Skip unknown field by decoding into empty interface
			var skip interface{}
			if err := dec.Decode(&skip); err != nil {
				return nil, err
			}
		}
	}

	return updates, nil
}

func streamAndConvertFixes(dec *json.Decoder, updates *v1alpha1.UpdateManifest) (*v1alpha1.UpdateManifest, error) {
	// Set of OS that are known to be part of Purls
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

	setOSDetails := false

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
						if !setOSDetails {
							setOSDetails = true
							updates.Metadata.OS.Type = installedInstance.Namespace
							updates.Metadata.OS.Version = extractDistro(installedInstance.Qualifiers)
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
