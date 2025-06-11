package main

import (
	"reflect"
	"testing"

	"github.com/project-copacetic/copacetic/pkg/types/v1alpha1"
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
			if got := newLineajeParser(); !reflect.DeepEqual(got, tt.want) {
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
						VulnerabilityID:  "CVE-1234-567",
					},
					{
						Name:             "musl",
						InstalledVersion: "1.2.4-r0",
						FixedVersion:     "1.2.4-r3",
						VulnerabilityID:  "CVE-1234-567",
					},
					{
						Name:             "libssl3",
						InstalledVersion: "3.1.0-r4",
						FixedVersion:     "3.1.8-r0",
						VulnerabilityID:  "CVE-1234-567",
					},
					{
						Name:             "musl-utils",
						InstalledVersion: "1.2.4-r0",
						FixedVersion:     "1.2.4-r3",
						VulnerabilityID:  "CVE-1234-567",
					},
					{
						Name:             "busybox-binsh",
						InstalledVersion: "1.36.0-r9",
						FixedVersion:     "1.36.1-r7",
						VulnerabilityID:  "CVE-1234-567",
					},
					{
						Name:             "libcrypto3",
						InstalledVersion: "3.1.0-r4",
						FixedVersion:     "3.1.8-r0",
						VulnerabilityID:  "CVE-1234-567",
					},
					{
						Name:             "busybox",
						InstalledVersion: "1.36.0-r9",
						FixedVersion:     "1.36.1-r7",
						VulnerabilityID:  "CVE-1234-567",
					},
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
			got, err := tt.parser.parse(tt.file)
			if (err != nil) != tt.wantErr {
				t.Fatalf("LineajeParser.parse() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LineajeParser.parse() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
