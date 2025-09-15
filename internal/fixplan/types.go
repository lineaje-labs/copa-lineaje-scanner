// Package fixplan type definitions for lineaje scanner report
package fixplan

// Metadata format defines different plan formats available when the "Recommend fix plan" is executed
type Metadata struct {
	BasicPlanComponentVulnerabilityFixes []Report `json:"basic_plan_component_vulnerability_fixes"`
}

// Report contains package and vulnerability information when the "Recommend fix plan" is executed
type Report struct {
	CurrentComponentPurl string `json:"current_component_purl"`
	TargetComponentPurl  string `json:"target_component_purl"`
	FixedVuln            int    `json:"fixed_vuln"`
	VulnerabilityId      string `json:"vulnerability_id"`
}

// ComponentFixData contains package vulnerable and fix information when the "Apply fix plan" is executed
type ComponentFixData struct {
	CurrentComponentPURL string `json:"Component Purl"`
	FixedComponentPURL   string `json:"Fixed_component_purl"`
}
