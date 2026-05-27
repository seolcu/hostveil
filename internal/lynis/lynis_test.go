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

func TestParseEntry_Evidence_FILE6405(t *testing.T) {
	f := parseEntry(`warning[]=FILE-6405|World writable file found|chmod o-w|/tmp/sensitive`, domain.SeverityHigh)
	if f == nil {
		t.Fatal("parseEntry returned nil")
	}
	if f.Evidence["path"] != "/tmp/sensitive" {
		t.Errorf("Evidence[path] = %q, want /tmp/sensitive", f.Evidence["path"])
	}
	if f.Evidence["extra"] != "/tmp/sensitive" {
		t.Errorf("Evidence[extra] = %q, want /tmp/sensitive", f.Evidence["extra"])
	}
}

func TestParseEntry_Evidence_ACCT9626(t *testing.T) {
	f := parseEntry(`warning[]=ACCT-9626|Password aging not set for user|chage -M 90|admin`, domain.SeverityHigh)
	if f == nil {
		t.Fatal("parseEntry returned nil")
	}
	if f.Evidence["user"] != "admin" {
		t.Errorf("Evidence[user] = %q, want admin", f.Evidence["user"])
	}
}

func TestParseEntry_Evidence_FIRE4513(t *testing.T) {
	f := parseEntry(`warning[]=FIRE-4513|Open port detected|Block with firewall|8080/tcp`, domain.SeverityHigh)
	if f == nil {
		t.Fatal("parseEntry returned nil")
	}
	if f.Evidence["port"] != "8080/tcp" {
		t.Errorf("Evidence[port] = %q, want 8080/tcp", f.Evidence["port"])
	}
}

func TestParseEntry_Evidence_Generic(t *testing.T) {
	f := parseEntry(`warning[]=AUTH-9286|SSH password auth enabled|Disable it|some extra info`, domain.SeverityHigh)
	if f == nil {
		t.Fatal("parseEntry returned nil")
	}
	if f.Evidence["extra"] != "some extra info" {
		t.Errorf("Evidence[extra] = %q, want 'some extra info'", f.Evidence["extra"])
	}
	if _, ok := f.Evidence["path"]; ok {
		t.Error("AUTH-9286 should not have Evidence[path]")
	}
}

func TestParseEntry_NoEvidence(t *testing.T) {
	f := parseEntry(`warning[]=AUTH-9286|SSH password auth enabled|Disable it`, domain.SeverityHigh)
	if f == nil {
		t.Fatal("parseEntry returned nil")
	}
	if len(f.Evidence) != 0 {
		t.Errorf("Evidence should be empty, got %v", f.Evidence)
	}
}

func TestParseManualEntry_Basic(t *testing.T) {
	f := parseManualEntry(`manual_event[]=Review firewall rules for unused ports`)
	if f == nil {
		t.Fatal("parseManualEntry returned nil")
	}
	if f.ID != "lynis.manual" {
		t.Errorf("ID = %q, want lynis.manual", f.ID)
	}
	if f.Title != "Review firewall rules for unused ports" {
		t.Errorf("Title = %q", f.Title)
	}
	if f.Severity != domain.SeverityMedium {
		t.Errorf("Severity = %v, want Medium", f.Severity)
	}
	if f.Remediation != domain.RemediationManual {
		t.Errorf("Remediation = %v, want Manual", f.Remediation)
	}
	if f.Service != "host" {
		t.Errorf("Service = %q, want host", f.Service)
	}
}

func TestParseManualEntry_Empty(t *testing.T) {
	f := parseManualEntry(`manual_event[]=`)
	if f != nil {
		t.Error("empty manual_event should return nil")
	}
}

func TestParseManualEntry_NoEquals(t *testing.T) {
	f := parseManualEntry(`just some text`)
	if f != nil {
		t.Error("entry without '=' should return nil")
	}
}

func TestParseExceptionEntry_Basic(t *testing.T) {
	f := parseExceptionEntry(`exception_event[]=AUTH-9286|Failed to read sshd_config|`)
	if f == nil {
		t.Fatal("parseExceptionEntry returned nil")
	}
	if f.ID != "lynis.exception.AUTH-9286" {
		t.Errorf("ID = %q, want lynis.exception.AUTH-9286", f.ID)
	}
	if f.Title != "Failed to read sshd_config" {
		t.Errorf("Title = %q", f.Title)
	}
	if f.Severity != domain.SeverityLow {
		t.Errorf("Severity = %v, want Low", f.Severity)
	}
}

func TestParseExceptionEntry_NoID(t *testing.T) {
	f := parseExceptionEntry(`exception_event[]=|Generic scan error|`)
	if f == nil {
		t.Fatal("parseExceptionEntry returned nil")
	}
	if f.ID != "lynis.exception" {
		t.Errorf("ID = %q, want lynis.exception", f.ID)
	}
	if f.Title != "Generic scan error" {
		t.Errorf("Title = %q", f.Title)
	}
}

func TestParseExceptionEntry_Empty(t *testing.T) {
	f := parseExceptionEntry(`exception_event[]=|`)
	if f != nil {
		t.Error("exception with empty message should return nil")
	}
}

func TestParseReport_WithAllTypes(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "report.dat")
	content := []byte(`warning[]=AUTH-9286|Disable SSH password authentication|Fix it
suggestion[]=FILE-6310|Fix /etc/shadow permissions|chmod
manual_event[]=Review firewall configuration
exception_event[]=KRNL-5780|Could not read sysctl value
`)
	if err := os.WriteFile(reportPath, content, 0644); err != nil {
		t.Fatal(err)
	}

	findings, err := parseReportFile(reportPath)
	if err != nil {
		t.Fatalf("parseReportFile: %v", err)
	}
	if len(findings) != 4 {
		t.Fatalf("parseReportFile returned %d findings, want 4", len(findings))
	}

	// Check each type is parsed
	types := map[string]bool{}
	for _, f := range findings {
		if f.ID == "lynis.AUTH-9286" {
			types["warning"] = true
		}
		if f.ID == "lynis.FILE-6310" {
			types["suggestion"] = true
		}
		if f.ID == "lynis.manual" {
			types["manual"] = true
		}
		if f.ID == "lynis.exception.KRNL-5780" {
			types["exception"] = true
		}
	}
	for _, name := range []string{"warning", "suggestion", "manual", "exception"} {
		if !types[name] {
			t.Errorf("missing finding type: %s", name)
		}
	}
}
