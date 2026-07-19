package core

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/check"
	composecheck "github.com/seolcu/hostveil/internal/check/compose"
	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/model"
)

// fakeRunner scripts LookPath and Run so the compose checker can be driven
// end-to-end without a real Docker daemon.
type fakeRunner struct {
	present map[string]bool
	lsJSON  string
}

func (f fakeRunner) LookPath(name string) (string, error) {
	if f.present[name] {
		return "/usr/bin/" + name, nil
	}
	return "", errors.New("not found")
}

func (f fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	if name == "docker" && strings.Join(args, " ") == "compose ls --all --format json" {
		return []byte(f.lsJSON), nil
	}
	return nil, errors.New("unexpected command: " + name + " " + strings.Join(args, " "))
}

func TestEngineScanEndToEnd(t *testing.T) {
	dir := t.TempDir()
	composePath := filepath.Join(dir, "docker-compose.yml")
	compose := `services:
  cache:
    image: redis:7
    ports:
      - "6379:6379"
  app:
    image: myapp
    privileged: true
`
	if err := os.WriteFile(composePath, []byte(compose), 0o600); err != nil {
		t.Fatal(err)
	}

	runner := fakeRunner{
		present: map[string]bool{"docker": true},
		lsJSON:  `[{"Name":"myproject","ConfigFiles":"` + composePath + `"}]`,
	}
	engine := New(Config{
		Registry: check.NewRegistry(composecheck.New()),
		Runner:   runner,
	})

	report := engine.Scan(context.Background(), nil)

	// The two critical/high misconfigurations must surface.
	ids := map[string]bool{}
	for _, f := range report.Findings {
		ids[f.ID] = true
		if f.Validate() != nil {
			t.Errorf("invalid finding reached report: %+v", f)
		}
	}
	if !ids["compose.ds018"] {
		t.Error("expected exposed-datastore finding")
	}
	if !ids["compose.ds001"] {
		t.Error("expected privileged finding")
	}

	// The container axis must be applicable and the score reduced.
	var containerApplicable bool
	for _, ax := range report.Score.Axes {
		if ax.Source == model.SourceCompose {
			containerApplicable = ax.Applicable
		}
	}
	if !containerApplicable {
		t.Error("container axis should be applicable after a compose scan ran")
	}
	if report.Score.Overall >= 100 {
		t.Errorf("score should be reduced, got %d", report.Score.Overall)
	}

	// Findings must be sorted most-severe-first.
	if len(report.Findings) >= 2 && report.Findings[0].Severity > report.Findings[1].Severity {
		t.Error("findings not sorted by severity")
	}

	// Current() should return the stored report.
	if cur, ran := engine.Current(); !ran || len(cur.Findings) != len(report.Findings) {
		t.Error("Current() did not return the stored report")
	}
}

// TestEngineSkipsComposeWithoutDocker verifies graceful skip: no Docker,
// no error, compose axis N/A, clean score.
func TestEngineSkipsComposeWithoutDocker(t *testing.T) {
	engine := New(Config{
		Registry: check.NewRegistry(composecheck.New()),
		Runner:   fakeRunner{present: map[string]bool{}},
	})
	report := engine.Scan(context.Background(), nil)

	if len(report.Findings) != 0 {
		t.Errorf("expected no findings, got %d", len(report.Findings))
	}
	for _, d := range report.Domains {
		if d.Source == model.SourceCompose && d.State != model.ScanSkipped {
			t.Errorf("compose domain state = %v, want skipped", d.State)
		}
	}
	if report.Score.Overall != 100 {
		t.Errorf("score with nothing scannable = %d, want 100", report.Score.Overall)
	}
}

// TestClassifyTakesTheMoreCautiousKind pins both directions of the rule
// that settles a finding's remediation.
//
// Down: the registry decides whether a fix exists at all, so a finding
// whose checker wanted a fix but has none registered becomes Manual and no
// UI can offer a button that leads nowhere.
//
// Up: the checker decides how much human judgment applying it needs, and a
// fix registered as Auto — a statement about its shape, one mechanical
// action — cannot talk it down. Without this, ssh.passwordauth ships as
// Auto and "fix all safe" disables password logins unattended on a host
// the user may only reach by password.
func TestClassifyTakesTheMoreCautiousKind(t *testing.T) {
	e := New(Config{Fixes: fix.Default()})

	cases := []struct {
		name    string
		finding model.Finding
		want    model.RemediationKind
		why     string
	}{
		{
			name: "checker Review beats registered Auto",
			finding: model.NewFinding("ssh.passwordauth", "password auth", model.SeverityMedium,
				model.SourceSSH, model.RemediationReview,
				model.WithEvidence("config", "/etc/ssh/sshd_config")),
			want: model.RemediationReview,
			why:  "a lockout risk must not be batch-applied",
		},
		{
			name: "checker Auto and registered Auto stays Auto",
			finding: model.NewFinding("compose.ds018", "exposed datastore", model.SeverityCritical,
				model.SourceCompose, model.RemediationAuto,
				model.WithService("cache"),
				model.WithMetadata("file", "/tmp/docker-compose.yml"),
				model.WithEvidence("port", "6379")),
			want: model.RemediationAuto,
			why:  "a reversible, unambiguous compose edit is safe unattended",
		},
		{
			name: "fixable but unregistered is demoted to Manual",
			finding: model.NewFinding("compose.ds016", "docker socket", model.SeverityCritical,
				model.SourceCompose, model.RemediationReview,
				model.WithService("app"),
				model.WithMetadata("file", "/tmp/docker-compose.yml")),
			want: model.RemediationManual,
			why:  "no registered fix means no fix button",
		},
		{
			name: "firewall has no fix at all",
			finding: model.NewFinding("firewall.inactive", "no firewall", model.SeverityHigh,
				model.SourceFirewall, model.RemediationReview),
			want: model.RemediationManual,
			why:  "enabling a firewall over SSH is not automatable safely",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := []model.Finding{tc.finding}
			e.classify(findings)
			if got := findings[0].Remediation; got != tc.want {
				t.Errorf("%s: remediation = %v, want %v (%s)", tc.finding.ID, got, tc.want, tc.why)
			}
		})
	}
}
