package parser

import (
	"reflect"
	"testing"

	"github.com/lineaje-labs/copacetic/pkg/types/v1alpha1"
)

// Test newLineajeParser returns a non-nil parser pointer
func TestNewLineajeParser(t *testing.T) {
	tests := []struct {
		name string
		want *LineajeParser
	}{
		{
			name: "valid parser",
			want: &LineajeParser{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewLineajeParser(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewLineajeParser() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Test LineajeParser.parse method with valid and invalid files
func TestLineajeParser_Parse(t *testing.T) {
	tests := []struct {
		name    string
		parser  *LineajeParser
		file    string
		want    *v1alpha1.UpdateManifest
		wantErr bool
	}{
		{
			name:   "valid report",
			parser: &LineajeParser{},
			file:   "testdata/lineaje_report.json",
			want: &v1alpha1.UpdateManifest{
				APIVersion: v1alpha1.APIVersion,
				Metadata: v1alpha1.Metadata{
					OS: v1alpha1.OS{
						Type:    "alpine",
						Version: "3.18.0",
					},
					Config: v1alpha1.Config{
						Arch: "x86_64",
					},
				},
				Updates: []v1alpha1.UpdatePackage{
					{
						Name:             "ssl_client",
						InstalledVersion: "1.36.0-r9",
						FixedVersion:     "1.36.1-r7",
						InstalledPURL:    "pkg:apk/alpine/ssl_client@1.36.0-r9?arch=x86_64&distro=alpine-3.18.0&upstream=busybox",
						FixedPURL:        "pkg:apk/alpine/ssl_client@1.36.1-r7",
						VulnerabilityID:  "CVE-1234-567",
					},
					{
						Name:             "musl",
						InstalledVersion: "1.2.4-r0",
						FixedVersion:     "1.2.4-r3",
						InstalledPURL:    "pkg:apk/alpine/musl@1.2.4-r0?arch=x86_64&distro=alpine-3.18.0",
						FixedPURL:        "pkg:apk/alpine/musl@1.2.4-r3",
						VulnerabilityID:  "CVE-1234-567",
					},
					{
						Name:             "libssl3",
						InstalledVersion: "3.1.0-r4",
						FixedVersion:     "3.1.8-r0",
						InstalledPURL:    "pkg:apk/alpine/libssl3@3.1.0-r4?arch=x86_64&distro=alpine-3.18.0&upstream=openssl",
						FixedPURL:        "pkg:apk/alpine/libssl3@3.1.8-r0",
						VulnerabilityID:  "CVE-1234-567",
					},
					{
						Name:             "musl-utils",
						InstalledVersion: "1.2.4-r0",
						FixedVersion:     "1.2.4-r3",
						InstalledPURL:    "pkg:apk/alpine/musl-utils@1.2.4-r0?arch=x86_64&distro=alpine-3.18.0&upstream=musl",
						FixedPURL:        "pkg:apk/alpine/musl-utils@1.2.4-r3",
						VulnerabilityID:  "CVE-1234-567",
					},
					{
						Name:             "busybox-binsh",
						InstalledVersion: "1.36.0-r9",
						FixedVersion:     "1.36.1-r7",
						InstalledPURL:    "pkg:apk/alpine/busybox-binsh@1.36.0-r9?arch=x86_64&distro=alpine-3.18.0&upstream=busybox",
						FixedPURL:        "pkg:apk/alpine/busybox-binsh@1.36.1-r7",
						VulnerabilityID:  "CVE-1234-567",
					},
					{
						Name:             "libcrypto3",
						InstalledVersion: "3.1.0-r4",
						FixedVersion:     "3.1.8-r0",
						InstalledPURL:    "pkg:apk/alpine/libcrypto3@3.1.0-r4?arch=x86_64&distro=alpine-3.18.0&upstream=openssl",
						FixedPURL:        "pkg:apk/alpine/libcrypto3@3.1.8-r0",
						VulnerabilityID:  "CVE-1234-567",
					},
					{
						Name:             "busybox",
						InstalledVersion: "1.36.0-r9",
						FixedVersion:     "1.36.1-r7",
						InstalledPURL:    "pkg:apk/alpine/busybox@1.36.0-r9?arch=x86_64&distro=alpine-3.18.0",
						FixedPURL:        "pkg:apk/alpine/busybox@1.36.1-r7",
						VulnerabilityID:  "CVE-1234-567",
					},
				},
				ImageDetails: v1alpha1.ImageDetail{
					Platform:        "docker-hub",
					ImageRepository: "docker.io",
					ImageName:       "alpine",
					ImageVersion:    "3.18.0",
					ImageDigest:     "sha256:02bb6f428431fbc2809c5d1b41eab5a68350194fb508869a33cb1af4444c9b11",
					Private:         false,
				},
			},
			wantErr: false,
		},
		{
			name:    "nonexistent file",
			parser:  &LineajeParser{},
			file:    "testdata/nonexistent_file.json",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid json",
			parser:  &LineajeParser{},
			file:    "testdata/invalid_report.json",
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.parser.Parse(tt.file)
			if (err != nil) != tt.wantErr {
				t.Fatalf("LineajeParser.parse() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != nil { // Set the plugin version as an empty variable as it will change for every build
				got.PluginVersion = ""
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LineajeParser.parse() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
