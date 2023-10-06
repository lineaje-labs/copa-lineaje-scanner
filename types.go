// Type definitions for fake scanner report
package main

// FakeReport contains OS, Arch, and Package information
type FakeReport struct {
	OSType    string
	OSVersion string
	Arch      string
	Packages  []FakePackage
}

// FakePackage contains package and vulnerability information
type FakePackage struct {
	Name             string
	InstalledVersion string
	FixedVersion     string
	VulnerabilityID  string
}
