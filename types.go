// Type definitions for lineaje scanner report
package main

// LineajeReport contains OS, Arch, and Package information
type LineajeReport struct {
	OSType    string
	OSVersion string
	Arch      string
	Metadata  Metadata `json:"meta_data"`
}

type Metadata struct {
	Basic_plan_component_vulnerability_fixes []Fixplan `json:"basic_plan_component_vulnerability_fixes"`
}

// Fixplan contains package and vulnerability information
type Fixplan struct {
	Current_component_purl     string `json:"current_component_purl"`
	Target_component_purl      string `json:"target_component_purl"`
	Fixed_vuln                 int 	  `json:"fixed_vuln"`
	Vulnerability_id           string `json:"vulnerability_id"`
}