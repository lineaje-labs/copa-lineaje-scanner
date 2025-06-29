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
			name: "valid report with all plan types",
			args: args{file: "testdata/lineaje_report.json"},
			want: &LineajeReport{
				Meta_data: LineajeVulnerability{
					Basic_plan_component_vulnerability_fixes: []Vulnerability{
						{
							Current_component_purl: "pkg:apk/alpine/libssl1.1@1.1.1i-r0?arch=aarch64&distro=alpine-3.14.0_alpha20210212&ups",
							Target_component_purl:  "pkg:apk/alpine/libssl1.1@1.1.1w-r1",
						},
						{
							Current_component_purl: "pkg:apk/alpine/ssl_client@1.33.0-r2?arch=aarch64&distro=alpine-3.14.0_alpha20210212&upstream=busybox",
							Target_component_purl:  "pkg:apk/alpine/ssl_client@1.33.1-r6",
						},
						{
							Current_component_purl: "pkg:apk/alpine/zlib@1.2.11-r3?arch=aarch64&distro=alpine-3.14.0_alpha20210212",
							Target_component_purl:  "pkg:apk/alpine/zlib@1.2.12-r2",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name:    "nonexistent file",
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
			name: "create new parser",
			want: &LineajeParser{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newLineajeParser(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newLineajeParser() = %v, want %v", got, tt.want)
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
			name: "valid report with all plan types",
			k:    &LineajeParser{},
			args: args{file: "testdata/lineaje_report.json"},
			want: &v1alpha1.UpdateManifest{
				APIVersion: v1alpha1.APIVersion,
				Metadata: v1alpha1.Metadata{
					OS: v1alpha1.OS{
						Type:    "alpine",
						Version: "3.14.0_alpha20210212",
					},
					Config: v1alpha1.Config{
						Arch: "aarch64",
					},
				},
				Updates: []v1alpha1.UpdatePackage{
					{
						Name:             "libssl1.1",
						InstalledVersion: "1.1.1i-r0",
						FixedVersion:     "1.1.1w-r1",
					},
					{
						Name:             "ssl_client",
						InstalledVersion: "1.33.0-r2",
						FixedVersion:     "1.33.1-r6",
					},
					{
						Name:             "zlib",
						InstalledVersion: "1.2.11-r3",
						FixedVersion:     "1.2.12-r2",
					},
				},
			},
			wantErr: false,
		},
		{
			name:    "nonexistent file",
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

func Test_getPackageVersion(t *testing.T) {
	tests := []struct {
		name string
		arg  string
		want string
	}{
		{
			name: "valid package with query params",
			arg:  "pkg:rpm/ol/python-libs@2.7.5-92.0.1.el7_9?arch=x86_64&upstream=python-2.7.5-92.0.1.el7_9.src.rpm&distro=ol-7.9",
			want: "2.7.5-92.0.1.el7_9",
		},
		{
			name: "valid package with epoch",
			arg:  "pkg:rpm/ol/python-libs@0:2.7.5-94.0.1.el7_9",
			want: "2.7.5-94.0.1.el7_9",
		},
		{
			name: "invalid package string",
			arg:  "pkg:rpm/ol/python-libs",
			want: "",
		},
		{
			name: "empty string",
			arg:  "",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getPackageVersion(tt.arg); got != tt.want {
				t.Errorf("getPackageVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getPackageName(t *testing.T) {
	tests := []struct {
		name string
		arg  string
		want string
	}{
		{
			name: "valid package with query params",
			arg:  "pkg:rpm/ol/python-libs@2.7.5-92.0.1.el7_9?arch=x86_64&upstream=python-2.7.5-92.0.1.el7_9.src.rpm&distro=ol-7.9",
			want: "python-libs",
		},
		{
			name: "valid package with epoch",
			arg:  "pkg:rpm/ol/python-libs@0:2.7.5-94.0.1.el7_9",
			want: "python-libs",
		},
		{
			name: "invalid package string",
			arg:  "pkg:rpm/ol/python-libs",
			want: "",
		},
		{
			name: "empty string",
			arg:  "",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getPackageName(tt.arg); got != tt.want {
				t.Errorf("getPackageName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getOsType(t *testing.T) {
	tests := []struct {
		name string
		arg  string
		want string
	}{
		{
			name: "amazon linux",
			arg:  "amzn",
			want: "amazon",
		},
		{
			name: "oracle linux",
			arg:  "ol",
			want: "ol",
		},
		{
			name: "debian",
			arg:  "debian",
			want: "debian",
		},
		{
			name: "empty string",
			arg:  "",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getOsType(tt.arg); got != tt.want {
				t.Errorf("getOsType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_checkComponentExist(t *testing.T) {
	tests := []struct {
		name     string
		packages v1alpha1.UpdatePackages
		arg      string
		want     bool
	}{
		{
			name: "component exists",
			packages: v1alpha1.UpdatePackages{
				{
					Name: "python-libs",
				},
			},
			arg:  "python-libs",
			want: true,
		},
		{
			name: "component does not exist",
			packages: v1alpha1.UpdatePackages{
				{
					Name: "python-libs",
				},
			},
			arg:  "curl",
			want: false,
		},
		{
			name:     "empty packages list",
			packages: v1alpha1.UpdatePackages{},
			arg:      "python-libs",
			want:     false,
		},
		{
			name: "empty component name",
			packages: v1alpha1.UpdatePackages{
				{
					Name: "python-libs",
				},
			},
			arg:  "",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkComponentExist(tt.packages, tt.arg); got != tt.want {
				t.Errorf("checkComponentExist() = %v, want %v", got, tt.want)
			}
		})
	}
} 