package fix

import (
	"os"
	"path/filepath"
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

func TestImagesMatch(t *testing.T) {
	tests := []struct {
		a, b string
		want  bool
	}{
		{"nginx:alpine", "nginx:alpine", true},
		{"nginx", "nginx:latest", true},
		{"nginx:latest", "nginx", true},
		{"nginx:alpine", "nginx", false},
		{"nginx:alpine", "nginx:1.24", false},
		{"", "nginx", false},
		{"nginx", "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.a+"_vs_"+tt.b, func(t *testing.T) {
			if got := imagesMatch(tt.a, tt.b); got != tt.want {
				t.Errorf("imagesMatch(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// TestResolveServiceForImage is a regression test for the trivy.cve-* fix
// bug where the fix used the image name (e.g. "nginx:alpine") as the
// compose service name, which always failed with "no such service".
func TestResolveServiceForImage(t *testing.T) {
	const yml = `services:
  web:
    image: nginx:alpine
  db:
    image: postgres:alpine
`
	dir := t.TempDir()
	path := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(path, []byte(yml), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		image string
		want  string
	}{
		{"nginx:alpine", "web"},
		{"postgres:alpine", "db"},
		{"redis:alpine", ""}, // not in file
	}
	for _, tt := range tests {
		t.Run(tt.image, func(t *testing.T) {
			got, err := resolveServiceForImage(path, tt.image)
			if err != nil {
				t.Fatalf("resolveServiceForImage: %v", err)
			}
			if got != tt.want {
				t.Errorf("resolveServiceForImage(%q) = %q, want %q", tt.image, got, tt.want)
			}
		})
	}
}
