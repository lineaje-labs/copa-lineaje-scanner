package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/lineaje-labs/copa-lineaje-scanner/internal/cmd"
	"github.com/lineaje-labs/copa-lineaje-scanner/internal/parser"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <image report>\n", os.Args[0])
		os.Exit(1)
	}
	if os.Args[1] == "version" {
		fmt.Print(cmd.GetVersion())
		os.Exit(0)
	}

	// Initialize the parser
	lineajeReportParser := parser.NewLineajeParser()

	// Get the image report from the command line
	imageReport := os.Args[1]

	report, err := lineajeReportParser.Parse(imageReport)
	if err != nil {
		fmt.Printf("error parsing report: %v\n", err)
		os.Exit(1)
	}

	// Serialize the standardized report and print it to stdout
	reportBytes, err := json.Marshal(report)
	if err != nil {
		fmt.Printf("Error serializing report: %v\n", err)
		os.Exit(1)
	}

	os.Stdout.Write(reportBytes)
}
