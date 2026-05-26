// Package scan provides shared scanning logic for trivy and lynis.
package scan

import (
	"fmt"
	"os/exec"

	"github.com/seolcu/hostveil/internal/domain"
	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/lynis"
	"github.com/seolcu/hostveil/internal/trivy"
)

// RunSingleTool runs one scan (trivy or lynis) and updates the ScanProgress.
// It checks for the tool, runs the scan, classifies findings, and finalizes
// when all tools are done.
func RunSingleTool(live *domain.ScanProgress, fixes *fix.Registry, tool string) {
	if _, err := exec.LookPath(tool); err != nil {
		live.SetToolStatus(tool, domain.ToolSkipped, "Not found (run 'hostveil setup')")
		return
	}

	live.SetToolStatus(tool, domain.ToolRunning, ScanningMessage(tool))

	var findings []domain.Finding
	var scanErr error
	switch tool {
	case "trivy":
		findings, scanErr = trivy.ScanAll()
	case "lynis":
		findings, scanErr = lynis.Scan()
	}

	if scanErr != nil {
		live.SetToolStatus(tool, domain.ToolError, fmt.Sprintf("Error: %v", scanErr))
	} else {
		fixes.Classify(findings)
		live.SetToolStatus(tool, domain.ToolDone, fmt.Sprintf("Found %d issues", len(findings)))
		live.AddFindings(findings)
	}

	if live.AllToolsDone() {
		live.Finalize()
	}
}

func ScanningMessage(tool string) string {
	switch tool {
	case "trivy":
		return "Scanning compose projects..."
	case "lynis":
		return "Auditing system hardening..."
	default:
		return "Scanning..."
	}
}
