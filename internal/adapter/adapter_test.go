package adapter

import (
	"testing"
)

func TestTrivyParsing(t *testing.T) {
	output := `{
		"Results": [{
			"Target": "library/nginx",
			"Vulnerabilities": [{
				"VulnerabilityID": "CVE-2024-0001",
				"PkgName": "openssl",
				"InstalledVersion": "1.1.1",
				"FixedVersion": "1.1.2",
				"Title": "OpenSSL vulnerability",
				"Severity": "HIGH",
				"Description": "A vulnerability in OpenSSL",
				"PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001"
			}]
		}]
	}`

	findings, err := parseTrivyImageOutput(output, "nginx:latest")
	if err != nil {
		t.Fatalf("parseTrivyImageOutput failed: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.ID != "trivy.cve-2024-0001" {
		t.Errorf("expected trivy.cve-2024-0001, got %s", f.ID)
	}
	if f.Severity.String() != "high" {
		t.Errorf("expected high severity, got %s", f.Severity)
	}
	if f.Source.String() != "trivy" {
		t.Errorf("expected trivy source, got %s", f.Source)
	}
	if f.Evidence["vulnerability_id"] != "CVE-2024-0001" {
		t.Errorf("expected CVE-2024-0001 evidence, got %s", f.Evidence["vulnerability_id"])
	}
}

func TestTrivyParsingEmptyOutput(t *testing.T) {
	findings, err := parseTrivyImageOutput(`{"Results":[]}`, "nginx:latest")
	if err != nil {
		t.Fatalf("parseTrivyImageOutput failed on empty: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestAdapterIsAvailableChecks(t *testing.T) {
	// These should not crash even if tools aren't installed
	_ = (&TrivyAdapter{}).IsAvailable()
	_ = (&LynisAdapter{}).IsAvailable()
}

func TestLynisParsing(t *testing.T) {
	output := `[!] File /etc/ssh/sshd_config has weak permissions
[suggestion] Install AIDE for file integrity monitoring
[+] Kernel hardening checks passed`

	findings, err := parseLynisOutput(output)
	if err != nil {
		t.Fatalf("parseLynisOutput failed: %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	if findings[0].Severity.String() != "high" {
		t.Errorf("expected high for warning [!], got %s", findings[0].Severity)
	}
}

func TestCommandRunnerTimeout(t *testing.T) {
	result := RunCommandWithTimeout(1, "sleep", "10")
	if result.Err == nil {
		t.Error("expected timeout error")
	}
}
