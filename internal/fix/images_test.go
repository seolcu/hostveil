package fix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/compose"
	"github.com/seolcu/hostveil/internal/domain"
)

func TestUpdateImageTagInCompose(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "docker-compose.yml")
	content := `services:
  web:
    image: nginx:1.24
  db:
    image: postgres:15
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	f, err := compose.Open(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := updateImageTagInCompose(f, "nginx:1.24", "nginx@sha256:abc123"); err != nil {
		t.Fatal(err)
	}

	if err := f.Save(); err != nil {
		t.Fatal(err)
	}

	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	savedStr := string(saved)
	if !strings.Contains(savedStr, "nginx@sha256:abc123") {
		t.Error("expected nginx image to be updated to digest")
	}
	if !strings.Contains(savedStr, "postgres:15") {
		t.Error("expected postgres image to remain unchanged")
	}
}

func TestRegisterImageFixes(t *testing.T) {
	r := New()
	registerImageFixes(r)

	f := r.Lookup("trivy.cve-2024-1234")
	if f == nil {
		t.Fatal("expected to find fix for trivy.cve-2024-1234")
	}
	if f.Label != "Update image tag or rebuild with patched base/package version. Verify with a new Trivy scan." {
		t.Errorf("unexpected label: %q", f.Label)
	}
	if len(f.Actions) != 0 {
		t.Errorf("expected 0 actions, got %d", len(f.Actions))
	}
}

func TestImageFixClassify(t *testing.T) {
	r := New()
	registerImageFixes(r)

	findings := []domain.Finding{
		{ID: "trivy.cve-2024-0001", Source: domain.SourceTrivy},
		{ID: "trivy.cve-2024-0002", Source: domain.SourceTrivy},
	}
	r.Classify(findings)

	for _, f := range findings {
		if f.Remediation != domain.RemediationManual {
			t.Errorf("expected RemediationManual for %q, got %v", f.ID, f.Remediation)
		}
	}
}
