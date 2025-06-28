package buildinfo

var BuildNum = "2025"

var Copyright = "Copyright (C) 2022-2025 Lineaje Inc - All rights reserved."
var Name = "copa-lineaje-scanner"
var Version = "1.0.0"

func GetFullVersion() string {
	fullVersion := Version
	// Update the Version with Build number if available
	if BuildNum != "" {
		fullVersion += "-" + BuildNum
	}
	return fullVersion
}
