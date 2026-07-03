package scan

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/seolcu/hostveil/internal/composeaudit"
	"github.com/seolcu/hostveil/internal/domain"
	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/history"
	"github.com/seolcu/hostveil/internal/lynis"
	"github.com/seolcu/hostveil/internal/trivy"
)

func RunSingleTool(live *domain.ScanProgress, fixes *fix.Registry, tool string) {
	if tool != "compose" {
		if _, err := exec.LookPath(tool); err != nil {
			live.SetToolStatus(tool, domain.ToolSkipped, "Not found (run 'hostveil setup')")
			finalizeIfDone(live)
			return
		}
	}

	live.SetToolStatus(tool, domain.ToolRunning, ScanningMessage(tool))

	var findings []domain.Finding
	var scanErr error
	switch tool {
	case "trivy":
		findings, scanErr = trivy.ScanAll(domain.DefaultRunner{})
	case "lynis":
		findings, scanErr = lynis.Scan(domain.DefaultRunner{})
	case "compose":
		findings, scanErr = composeaudit.ScanAll(domain.DefaultRunner{})
	default:
		live.SetToolStatus(tool, domain.ToolSkipped, "Unknown tool")
		finalizeIfDone(live)
		return
	}

	if scanErr != nil {
		if len(findings) > 0 {
			fixes.Classify(findings)
			overrideCVEClassifications(findings)
			live.AddFindings(findings)
			live.SetToolStatus(tool, domain.ToolDegraded,
				fmt.Sprintf("Partial: %d issues, %s", len(findings), summarizeScanError(scanErr)))
		} else {
			live.SetToolStatus(tool, domain.ToolError, "Error: "+summarizeScanError(scanErr))
		}
	} else {
		fixes.Classify(findings)
		overrideCVEClassifications(findings)
		live.SetToolStatus(tool, domain.ToolDone, fmt.Sprintf("Found %d issues", len(findings)))
		live.AddFindings(findings)
	}

	finalizeIfDone(live)
}

func finalizeIfDone(live *domain.ScanProgress) {
	if live.AllToolsDone() {
		live.Finalize()
		// Save scan snapshot to history (best-effort)
		go func() {
			snap := live.Snapshot()
			_ = history.SaveScan(snap) // best-effort; scan already complete
		}()
	}
}

func summarizeScanError(err error) string {
	if err == nil {
		return ""
	}
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "config scan"):
		return "config scan failed"
	case strings.Contains(s, "image scan"):
		return "image scan failed"
	case strings.Contains(s, "compose"):
		return "compose discovery failed"
	case strings.Contains(s, "non-json") || strings.Contains(s, "invalid json"):
		return "scanner output unreadable"
	case strings.Contains(s, "timeout") || strings.Contains(s, "deadline"):
		return "scan timed out"
	default:
		msg := err.Error()
		if len(msg) > 72 {
			return msg[:69] + "..."
		}
		return msg
	}
}

func ScanningMessage(tool string) string {
	switch tool {
	case "trivy":
		return "Scanning container images..."
	case "lynis":
		return "Auditing system hardening..."
	case "compose":
		return "Scanning compose projects..."
	default:
		return "Scanning..."
	}
}

// overrideCVEClassifications sets Trivy vulnerability findings without a
// FixedVersion to Manual. Findings with a FixedVersion keep their Auto
// classification (pull + redeploy). This covers every Trivy vulnerability
// ID, not just CVE-prefixed ones: Trivy reports some advisories (e.g. from
// GitHub Security Advisories / npm, pip, gem ecosystems) under a bare
// GHSA-style VulnerabilityID with no CVE ever assigned, so restricting
// this to "trivy.cve-" would leave those permanently unclassified
// (Unavailable), contradicting the invariant that Unavailable is never
// user-visible after a complete scan.
func overrideCVEClassifications(findings []domain.Finding) {
	for i := range findings {
		if strings.HasPrefix(findings[i].ID, "trivy.") {
			if findings[i].Evidence == nil || findings[i].Evidence["fixed_version"] == "" {
				findings[i].Remediation = domain.RemediationManual
				if findings[i].HowToFix == "" {
					findings[i].HowToFix = "No patched version available yet. Monitor upstream for updates."
				}
			}
		}
	}
}
