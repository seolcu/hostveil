package scan

import (
	"testing"

	"github.com/seolcu/hostveil/internal/domain"
)

// TestOverrideCVEClassifications_NoFixedVersion asserts the primary
// path: CVE findings without a FixedVersion in evidence are flipped
// to RemediationManual, and a how-to-fix is added if missing.
func TestOverrideCVEClassifications_NoFixedVersion(t *testing.T) {
	findings := []domain.Finding{
		{ID: "trivy.cve-2024-1234", Source: domain.SourceTrivy, Remediation: domain.RemediationAuto},
		{ID: "trivy.cve-2024-5678", Source: domain.SourceTrivy, Remediation: domain.RemediationAuto, HowToFix: "already set"},
	}
	overrideCVEClassifications(findings)

	if findings[0].Remediation != domain.RemediationManual {
		t.Errorf("findings[0].Remediation = %v, want Manual", findings[0].Remediation)
	}
	if findings[0].HowToFix == "" {
		t.Error("findings[0].HowToFix empty, want default message")
	}
	if findings[1].Remediation != domain.RemediationManual {
		t.Errorf("findings[1].Remediation = %v, want Manual", findings[1].Remediation)
	}
	if findings[1].HowToFix != "already set" {
		t.Errorf("findings[1].HowToFix = %q, want preserved", findings[1].HowToFix)
	}
}

// TestOverrideCVEClassifications_WithFixedVersion asserts the
// negative case: CVE findings WITH a FixedVersion keep their
// RemediationAuto classification.
func TestOverrideCVEClassifications_WithFixedVersion(t *testing.T) {
	findings := []domain.Finding{
		{
			ID:          "trivy.cve-2024-1234",
			Source:      domain.SourceTrivy,
			Remediation: domain.RemediationAuto,
			Evidence:    map[string]string{"fixed_version": "3.0.1"},
		},
	}
	overrideCVEClassifications(findings)
	if findings[0].Remediation != domain.RemediationAuto {
		t.Errorf("Remediation = %v, want Auto (FixedVersion present)", findings[0].Remediation)
	}
}

// TestOverrideCVEClassifications_NonCVEUnchanged asserts non-CVE
// findings are not touched even if they have empty evidence.
func TestOverrideCVEClassifications_NonCVEUnchanged(t *testing.T) {
	findings := []domain.Finding{
		{ID: "compose.ds001", Source: domain.SourceCompose, Remediation: domain.RemediationAuto},
		{ID: "lynis.AUTH-9286", Source: domain.SourceLynis, Remediation: domain.RemediationAuto},
	}
	overrideCVEClassifications(findings)
	for i, f := range findings {
		if f.Remediation != domain.RemediationAuto {
			t.Errorf("findings[%d].Remediation = %v, want Auto (non-CVE must not be changed)", i, f.Remediation)
		}
	}
}

// TestOverrideCVEClassifications_EmptyEvidence asserts that a
// missing evidence map is treated like an empty fixed_version
// (the finding becomes Manual). nil map reads return the zero value
// in Go, so the function must not panic on missing keys.
func TestOverrideCVEClassifications_EmptyEvidence(t *testing.T) {
	findings := []domain.Finding{
		{ID: "trivy.cve-2024-1234", Source: domain.SourceTrivy, Remediation: domain.RemediationAuto, Evidence: map[string]string{}},
		{ID: "trivy.cve-2024-5678", Source: domain.SourceTrivy, Remediation: domain.RemediationAuto, Evidence: map[string]string{"other": "value"}},
	}
	overrideCVEClassifications(findings)
	if findings[0].Remediation != domain.RemediationManual {
		t.Errorf("findings[0].Remediation = %v, want Manual", findings[0].Remediation)
	}
	if findings[1].Remediation != domain.RemediationManual {
		t.Errorf("findings[1].Remediation = %v, want Manual (no fixed_version key)", findings[1].Remediation)
	}
}

// TestOverrideCVEClassifications_GHSAOnlyFinding is a regression test:
// Trivy reports some vulnerabilities under a bare GHSA-style
// VulnerabilityID with no CVE ever assigned (common in npm/pip/gem
// ecosystem advisories sourced from GitHub Security Advisories). Before
// this fix, overrideCVEClassifications only matched the "trivy.cve-"
// prefix, so a "trivy.ghsa-..." finding was never touched here and
// never matched the fix registry's "trivy.cve-*" pattern either --
// leaving it stuck at RemediationUnavailable forever, contradicting the
// documented invariant that Unavailable is never user-visible after a
// complete scan (AGENTS.md).
func TestOverrideCVEClassifications_GHSAOnlyFinding(t *testing.T) {
	findings := []domain.Finding{
		{ID: "trivy.ghsa-xqr8-7jwr-rhp7", Source: domain.SourceTrivy, Remediation: domain.RemediationUnavailable},
		{
			// Simulates state after fixes.Classify() ran first in the real
			// pipeline (RunSingleTool) and matched the "trivy.*" wildcard,
			// setting Auto. This asserts overrideCVEClassifications leaves
			// an Auto-classified, FixedVersion-present GHSA finding alone.
			ID:          "trivy.ghsa-aaaa-bbbb-cccc",
			Source:      domain.SourceTrivy,
			Remediation: domain.RemediationAuto,
			Evidence:    map[string]string{"fixed_version": "2.31.0"},
		},
	}
	overrideCVEClassifications(findings)

	if findings[0].Remediation != domain.RemediationManual {
		t.Errorf("GHSA finding without FixedVersion: Remediation = %v, want Manual (not stuck at Unavailable)", findings[0].Remediation)
	}
	if findings[0].HowToFix == "" {
		t.Error("GHSA finding without FixedVersion should get a default HowToFix message")
	}
	if findings[1].Remediation != domain.RemediationAuto {
		t.Errorf("GHSA finding WITH FixedVersion: Remediation = %v, want Auto (unchanged)", findings[1].Remediation)
	}
}
