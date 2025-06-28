package cmd

import (
	"fmt"

	"github.com/lineaje-labs/copa-lineaje-scanner/internal/buildinfo"
)

func GetVersion() string {
	Copyright := buildinfo.Copyright
	Name := buildinfo.Name
	Version := buildinfo.Version
	BuildNum := buildinfo.BuildNum
	return fmt.Sprintf("%s version %s-%s\n%s\n", Name, Version, BuildNum, Copyright)
}
