package cve

import (
	"context"
	"errors"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

type fakeRunner struct{ present map[string]bool }

func (f fakeRunner) LookPath(name string) (string, error) {
	if f.present[name] {
		return "/usr/bin/" + name, nil
	}
	return "", errors.New("not found")
}
func (fakeRunner) Run(context.Context, string, ...string) ([]byte, error) {
	return nil, errors.New("unused")
}

func TestCVESkipsWithoutTrivy(t *testing.T) {
	ok, reason := New().Available(context.Background(), platform.Env{Runner: fakeRunner{present: map[string]bool{"docker": true}}})
	if ok {
		t.Error("should skip without Trivy")
	}
	if reason == "" {
		t.Error("skip should have a reason")
	}
}

func TestCVEAvailableWithBothTools(t *testing.T) {
	ok, _ := New().Available(context.Background(), platform.Env{Runner: fakeRunner{present: map[string]bool{"trivy": true, "docker": true}}})
	if !ok {
		t.Error("should be available with trivy and docker present")
	}
}

func TestParseTrivyFixedAndUnfixed(t *testing.T) {
	out := `{
      "Results": [
        {"Vulnerabilities": [
          {"VulnerabilityID":"CVE-2021-1234","PkgName":"openssl","InstalledVersion":"1.0","FixedVersion":"1.1","Severity":"HIGH","Title":"buffer overflow","PrimaryURL":"http://x"},
          {"VulnerabilityID":"CVE-2022-9999","PkgName":"zlib","InstalledVersion":"1.2","FixedVersion":"","Severity":"CRITICAL","Title":"rce"}
        ]}
      ]
    }`
	fs, err := parseTrivy([]byte(out), "myimage:1", "web")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(fs))
	}
	byID := map[string]model.Finding{}
	for _, f := range fs {
		if f.Validate() != nil {
			t.Errorf("invalid finding %s", f.ID)
		}
		byID[f.ID] = f
	}

	fixed := byID["cve.cve-2021-1234"]
	if fixed.Remediation != model.RemediationReview {
		t.Errorf("fixable CVE should be Review, got %v", fixed.Remediation)
	}
	if fixed.Severity != model.SeverityHigh {
		t.Errorf("severity = %v, want high", fixed.Severity)
	}

	// A CVE with no upstream fix is Unavailable — set at the source, no
	// post-scan override band-aid.
	unfixed := byID["cve.cve-2022-9999"]
	if unfixed.Remediation != model.RemediationUnavailable {
		t.Errorf("unfixable CVE should be Unavailable, got %v", unfixed.Remediation)
	}
}

func TestParseTrivyGarbageErrors(t *testing.T) {
	if _, err := parseTrivy([]byte("not json"), "img", "svc"); err == nil {
		t.Error("expected error on non-JSON trivy output")
	}
}

// FuzzParseTrivy ensures untrusted scanner output never panics the parser.
func FuzzParseTrivy(f *testing.F) {
	f.Add([]byte(`{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-1"}]}]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`garbage`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseTrivy(data, "img", "svc")
	})
}
