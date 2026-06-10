package fix

import (
	"testing"

	"github.com/seolcu/hostveil/internal/domain"
)

func TestRegisterImageFixes(t *testing.T) {
	r := New()
	registerImageFixes(r)

	f := r.Lookup("trivy.cve-2024-1234")
	if f == nil {
		t.Fatal("expected to find fix for trivy.cve-2024-1234")
	}
	if f.Label != "Pull latest image and redeploy service" {
		t.Errorf("unexpected label: %q", f.Label)
	}
	if len(f.Actions) != 1 {
		t.Errorf("expected 1 action, got %d", len(f.Actions))
	}
}

func TestImageFixClassify_WithFixedVersion(t *testing.T) {
	r := New()
	registerImageFixes(r)

	findings := []domain.Finding{
		{ID: "trivy.cve-2024-0001", Source: domain.SourceTrivy, Evidence: map[string]string{"fixed_version": "1.25.0"}},
	}
	r.Classify(findings)

	// With 1 action and no explicit Kind, Class() returns Auto
	if findings[0].Remediation != domain.RemediationAuto {
		t.Errorf("expected RemediationAuto for CVE with FixedVersion, got %v", findings[0].Remediation)
	}
}

func TestImageFixClassify_NoFixedVersion(t *testing.T) {
	r := New()
	registerImageFixes(r)

	findings := []domain.Finding{
		{ID: "trivy.cve-2024-0002", Source: domain.SourceTrivy, Evidence: map[string]string{}},
	}
	r.Classify(findings)

	// After Classify, the fix sets Auto. But scan.go's overrideCVEClassifications
	// would set it to Manual. This test only checks Classify behavior.
	if findings[0].Remediation != domain.RemediationAuto {
		t.Errorf("expected RemediationAuto from Classify alone (override happens in scan.go), got %v", findings[0].Remediation)
	}
}
