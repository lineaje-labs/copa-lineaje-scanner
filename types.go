// Type definitions for fake scanner report
package main

// FakeReport contains OS, Arch, and Package information
type LineajeReport struct {
	Meta_data LineajeVulnerability `json:"meta_data"`
}

type LineajeVulnerability struct {
	Basic_plan_component_vulnerability_fixes     []Vulnerability `json:"basic_plan_component_vulnerability_fixes"`
	Balanced_plan_components_vulnerability_fixes []Vulnerability `json:"balanced_plan_components_vulnerability_fixes"`
	Comprehensive_plan_components []Vulnerability `json:"comprehensive_plan_components"`
}

// FakePackage contains package and vulnerability information
type Vulnerability struct {
	Current_component_purl string `json:"current_component_purl"`
	Target_component_purl  string `json:"target_component_purl"`
	Vulnerability_id       string `json:"vulnerability_id"`
}