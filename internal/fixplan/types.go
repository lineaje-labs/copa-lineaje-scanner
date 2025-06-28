// Package fixplan type definitions for lineaje scanner report
package fixplan

type Metadata struct {
	BasicPlanComponentVulnerabilityFixes []Report `json:"basic_plan_component_vulnerability_fixes"`
}

// Report contains package and vulnerability information
type Report struct {
	CurrentComponentPurl string `json:"current_component_purl"`
	TargetComponentPurl  string `json:"target_component_purl"`
	FixedVuln            int    `json:"fixed_vuln"`
	VulnerabilityId      string `json:"vulnerability_id"`
}
