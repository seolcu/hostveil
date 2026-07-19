package cve

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

type fakeRunner struct {
	present    map[string]bool
	daemonDown bool
}

func (f fakeRunner) LookPath(name string) (string, error) {
	if f.present[name] {
		return "/usr/bin/" + name, nil
	}
	return "", errors.New("not found")
}
func (f fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	if name == "docker" && strings.Join(args, " ") == "version --format {{.Server.Version}}" {
		if f.daemonDown {
			return nil, errors.New("permission denied while trying to connect to the Docker daemon socket")
		}
		return []byte("27.0.3\n"), nil
	}
	return nil, errors.New("unexpected command: " + name + " " + strings.Join(args, " "))
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

// The bug this guards: the docker CLI on PATH says nothing about whether this
// user may talk to the socket. Treating presence as reachability let the scan
// proceed, fail on every image, and report zero vulnerabilities — which scores
// as a perfect 100 on a host that was never actually scanned.
func TestCVESkipsWhenDaemonUnreachable(t *testing.T) {
	r := fakeRunner{present: map[string]bool{"trivy": true, "docker": true}, daemonDown: true}
	ok, reason := New().Available(context.Background(), platform.Env{Runner: r})
	if ok {
		t.Fatal("should skip when the Docker daemon cannot be reached")
	}
	if !strings.Contains(reason, "sudo") {
		t.Errorf("reason should tell the user how to fix it, got %q", reason)
	}
}

// scriptRunner scripts a full Check(): a compose project on disk plus a
// per-image Trivy result (or failure).
type scriptRunner struct {
	lsJSON   string
	trivy    map[string]string // image → JSON output
	trivyErr map[string]bool   // image → fail
	argv     []string          // the last trivy argv, for flag assertions
}

func (s *scriptRunner) LookPath(name string) (string, error) { return "/usr/bin/" + name, nil }

func (s *scriptRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	joined := strings.Join(args, " ")
	switch {
	case name == "docker" && joined == "version --format {{.Server.Version}}":
		return []byte("27.0.3\n"), nil
	case name == "docker" && joined == "compose ls --all --format json":
		return []byte(s.lsJSON), nil
	case name == "trivy":
		s.argv = args
		image := args[len(args)-1]
		if s.trivyErr[image] {
			return nil, errors.New("failed to download vulnerability DB")
		}
		return []byte(s.trivy[image]), nil
	}
	return nil, errors.New("unexpected command: " + name + " " + joined)
}

// composeProject writes a two-service compose file and returns the runner
// wired to discover it.
func composeProject(t *testing.T) *scriptRunner {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "docker-compose.yml")
	yml := "services:\n  cache:\n    image: redis:7\n  db:\n    image: postgres:13\n"
	if err := os.WriteFile(path, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	return &scriptRunner{
		lsJSON:   `[{"Name":"stack","ConfigFiles":"` + path + `"}]`,
		trivy:    map[string]string{},
		trivyErr: map[string]bool{},
	}
}

const oneVuln = `{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-2021-1234","PkgName":"openssl","InstalledVersion":"1.0","FixedVersion":"1.1","Severity":"HIGH","Title":"overflow"}]}]}`

// Some images unscannable is Degraded: the findings we did get are real and
// worth keeping, but the picture is incomplete and must say so.
func TestCVEPartialScanIsDegraded(t *testing.T) {
	r := composeProject(t)
	r.trivy["redis:7"] = oneVuln
	r.trivyErr["postgres:13"] = true

	findings, err := New().Check(context.Background(), platform.Env{Runner: r})

	var partial *check.PartialError
	if !errors.As(err, &partial) {
		t.Fatalf("expected a PartialError, got %v", err)
	}
	if partial.Covered != 1 || partial.Total != 2 {
		t.Errorf("coverage = %d/%d, want 1/2", partial.Covered, partial.Total)
	}
	if len(findings) != 1 {
		t.Errorf("partial scan should keep the findings it did get, got %d", len(findings))
	}
}

// Every image failing is not a partial result, it is a failed one. It must be
// an ordinary error so the axis drops out of scoring entirely — a Degraded
// domain is still scored, and would hand back the false 100 all over again.
func TestCVEAllImagesFailingIsError(t *testing.T) {
	r := composeProject(t)
	r.trivyErr["redis:7"] = true
	r.trivyErr["postgres:13"] = true

	findings, err := New().Check(context.Background(), platform.Env{Runner: r})
	if err == nil {
		t.Fatal("expected an error when no image could be scanned")
	}
	var partial *check.PartialError
	if errors.As(err, &partial) {
		t.Error("a total failure must not be reported as partial coverage")
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

func TestCVECleanScanIsNotDegraded(t *testing.T) {
	r := composeProject(t)
	r.trivy["redis:7"] = `{"Results":[]}`
	r.trivy["postgres:13"] = `{"Results":[]}`

	if _, err := New().Check(context.Background(), platform.Env{Runner: r}); err != nil {
		t.Errorf("a fully successful scan should not error: %v", err)
	}
}

// A host with no containers genuinely has no image vulnerabilities — that is a
// clean Done, not a degraded or failed scan.
func TestCVENoImagesIsClean(t *testing.T) {
	r := composeProject(t)
	r.lsJSON = `[]`

	findings, err := New().Check(context.Background(), platform.Env{Runner: r})
	if err != nil {
		t.Errorf("no images should not be an error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

// Trivy pulls from a remote registry when it cannot read an image locally, so
// an unbounded scan can hang for as long as the network allows.
func TestCVEPassesTimeoutToTrivy(t *testing.T) {
	r := composeProject(t)
	r.trivy["redis:7"] = `{"Results":[]}`
	r.trivy["postgres:13"] = `{"Results":[]}`

	if _, err := New().Check(context.Background(), platform.Env{Runner: r}); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(r.argv, "--timeout") {
		t.Errorf("trivy invoked without --timeout: %v", r.argv)
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
