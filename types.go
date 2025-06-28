// Type definitions for lineaje scanner report
package main

// LineajeReport contains OS, Arch, and Package information
type LineajeReport struct {
	OSType    string
	OSVersion string
	Arch      string
	Packages  []LineajePackage
}

// LineajePackage contains package and vulnerability information
type LineajePackage struct {
	Name             string
	InstalledVersion string
	FixedVersion     string
	VulnerabilityID  string
}
