package lynis

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/seolcu/hostveil/internal/domain"
)

func TestParseEntry_Warning(t *testing.T) {
	f := parseEntry(`warning[]=AUTH-9286|SSH password authentication is enabled|Disable password auth in sshd_config|extra`, domain.SeverityHigh)
	if f == nil {
		t.Fatal("parseEntry returned nil")
	}
	if f.ID != "lynis.AUTH-9286" {
		t.Errorf("ID = %q, want lynis.AUTH-9286", f.ID)
	}
	if f.Title != "SSH password authentication is enabled" {
		t.Errorf("Title = %q, want SSH password...", f.Title)
	}
	if f.HowToFix != "Disable password auth in sshd_config" {
		t.Errorf("HowToFix = %q, want Disable password auth...", f.HowToFix)
	}
	if f.Severity != domain.SeverityHigh {
		t.Errorf("Severity = %v, want High", f.Severity)
	}
	if f.Source != domain.SourceLynis {
		t.Errorf("Source = %v, want Lynis", f.Source)
	}
	if f.Service != "host" {
		t.Errorf("Service = %q, want host", f.Service)
	}
}

func TestParseEntry_Suggestion(t *testing.T) {
	f := parseEntry(`suggestion[]=FILE-6310|Check file permissions on /etc/shadow|chmod`, domain.SeverityMedium)
	if f == nil {
		t.Fatal("parseEntry returned nil")
	}
	if f.ID != "lynis.FILE-6310" {
		t.Errorf("ID = %q, want lynis.FILE-6310", f.ID)
	}
	if f.Severity != domain.SeverityMedium {
		t.Errorf("Severity = %v, want Medium", f.Severity)
	}
}

func TestParseEntry_Minimal(t *testing.T) {
	f := parseEntry(`warning[]=TEST-1|just a title`, domain.SeverityLow)
	if f == nil {
		t.Fatal("parseEntry returned nil")
	}
	if f.ID != "lynis.TEST-1" {
		t.Errorf("ID = %q", f.ID)
	}
	if f.Title != "just a title" {
		t.Errorf("Title = %q", f.Title)
	}
	if f.HowToFix != "" {
		t.Errorf("HowToFix should be empty, got %q", f.HowToFix)
	}
}

func TestParseEntry_EmptyID(t *testing.T) {
	f := parseEntry(`warning[]=|description`, domain.SeverityHigh)
	if f != nil {
		t.Error("entry with empty ID should return nil")
	}
}

func TestParseEntry_EmptyDescription(t *testing.T) {
	f := parseEntry(`warning[]=TEST-1|`, domain.SeverityHigh)
	if f != nil {
		t.Error("entry with empty description should return nil")
	}
}

func TestParseEntry_NoEquals(t *testing.T) {
	f := parseEntry(`just some text without equals sign`, domain.SeverityHigh)
	if f != nil {
		t.Error("entry without '=' should return nil")
	}
}

func TestParseEntry_TooFewParts(t *testing.T) {
	f := parseEntry(`warning[]=ONLY_ID`, domain.SeverityHigh)
	if f != nil {
		t.Error("entry without pipe should return nil")
	}
}

func TestParseReport(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "report.dat")
	content := []byte(`warning[]=AUTH-9286|Disable SSH password authentication|Fix it
suggestion[]=FILE-6310|Fix /etc/shadow permissions|chmod
warning[]=TEST-2|Another warning with no remediation
`)
	if err := os.WriteFile(reportPath, content, 0644); err != nil {
		t.Fatal(err)
	}

	findings, err := parseReportFile(reportPath)
	if err != nil {
		t.Fatalf("parseReportFile: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("parseReportFile returned %d findings, want 3", len(findings))
	}

	if findings[0].ID != "lynis.AUTH-9286" {
		t.Errorf("findings[0].ID = %q", findings[0].ID)
	}
	if findings[0].Severity != domain.SeverityHigh {
		t.Errorf("findings[0].Severity = %v, want High", findings[0].Severity)
	}
	if findings[1].ID != "lynis.FILE-6310" {
		t.Errorf("findings[1].ID = %q", findings[1].ID)
	}
	if findings[1].Severity != domain.SeverityMedium {
		t.Errorf("findings[1].Severity = %v, want Medium", findings[1].Severity)
	}
}

func TestParseReport_Empty(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "empty.dat")
	os.WriteFile(reportPath, []byte{}, 0644)

	findings, err := parseReportFile(reportPath)
	if err != nil {
		t.Fatalf("parseReportFile: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("empty report should return 0 findings, got %d", len(findings))
	}
}
