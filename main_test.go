package main

import (
	"reflect"
	"testing"

	v1alpha1 "github.com/project-copacetic/copacetic/pkg/types/v1alpha1"
)

func Test_parseLineajeReport(t *testing.T) {
	type args struct {
		file string
	}
	tests := []struct {
		name    string
		args    args
		want    *LineajeReport
		wantErr bool
	}{
		{
			name: "valid report",
			args: args{file: "testdata/lineaje_report.json"},
			want: &LineajeReport{
				Metadata: Metadata{
					Basic_plan_component_vulnerability_fixes: []Fixplan{
						{
							Current_component_purl: "pkg:apk/alpine/ssl_client@1.36.0-r9?arch=x86_64&distro=alpine-3.18.0&upstream=busybox",
							Target_component_purl: "pkg:apk/alpine/ssl_client@1.36.1-r7",
							Fixed_vuln: 5,
							Vulnerability_id: "CVE-1234-567",
						},
						{
							Current_component_purl: "pkg:apk/alpine/musl@1.2.4-r0?arch=x86_64&distro=alpine-3.18.0",
							Target_component_purl: "pkg:apk/alpine/musl@1.2.4-r3",
							Fixed_vuln: 1,
							Vulnerability_id: "CVE-1234-567",
						},
						{
							Current_component_purl: "pkg:apk/alpine/libssl3@3.1.0-r4?arch=x86_64&distro=alpine-3.18.0&upstream=openssl",
							Target_component_purl: "pkg:apk/alpine/libssl3@3.1.8-r0",
							Fixed_vuln: 16,
							Vulnerability_id: "CVE-1234-567",
						},
						{
							Current_component_purl: "pkg:apk/alpine/musl-utils@1.2.4-r0?arch=x86_64&distro=alpine-3.18.0&upstream=musl",
							Target_component_purl: "pkg:apk/alpine/musl-utils@1.2.4-r3",
							Fixed_vuln: 1,
							Vulnerability_id: "CVE-1234-567",
						},
						{
							Current_component_purl: "pkg:apk/alpine/busybox-binsh@1.36.0-r9?arch=x86_64&distro=alpine-3.18.0&upstream=busybox",
							Target_component_purl: "pkg:apk/alpine/busybox-binsh@1.36.1-r7",
							Fixed_vuln: 5,
							Vulnerability_id: "CVE-1234-567",
						},
						{
							Current_component_purl: "pkg:apk/alpine/libcrypto3@3.1.0-r4?arch=x86_64&distro=alpine-3.18.0&upstream=openssl",
							Target_component_purl: "pkg:apk/alpine/libcrypto3@3.1.8-r0",
							Fixed_vuln: 16,
							Vulnerability_id: "CVE-1234-567",
						},
						{
							Current_component_purl: "pkg:apk/alpine/busybox@1.36.0-r9?arch=x86_64&distro=alpine-3.18.0",
							Target_component_purl: "pkg:apk/alpine/busybox@1.36.1-r7",
							Fixed_vuln: 5,
							Vulnerability_id: "CVE-1234-567",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name:    "invalid file",
			args:    args{file: "testdata/nonexistent_file.json"},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid json",
			args:    args{file: "testdata/invalid_report.json"},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseLineajeReport(tt.args.file)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseLineajeReport() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseLineajeReport() = %v, want %v", got, tt.want)
			}
		})
	}
}

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

func TestLineajeParser_Parse(t *testing.T) {
	type args struct {
		file string
	}
	tests := []struct {
		name    string
		k       *LineajeParser
		args    args
		want    *v1alpha1.UpdateManifest
		wantErr bool
	}{
		{
			name: "valid report",
			k:    &LineajeParser{},
			args: args{file: "testdata/lineaje_report.json"},
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
			name:    "invalid file",
			k:       &LineajeParser{},
			args:    args{file: "testdata/nonexistent_file.json"},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid json",
			k:       &LineajeParser{},
			args:    args{file: "testdata/invalid_report.json"},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.k.parse(tt.args.file)
			if (err != nil) != tt.wantErr {
				t.Errorf("LineajeParser.Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LineajeParser.Parse() = %v, want %v", got, tt.want)
			}
		})
	}
}
