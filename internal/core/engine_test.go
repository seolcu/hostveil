package core

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/seolcu/hostveil/internal/check"
	composecheck "github.com/seolcu/hostveil/internal/check/compose"
	cvecheck "github.com/seolcu/hostveil/internal/check/cve"
	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/history"
	"github.com/seolcu/hostveil/internal/model"
)

// fakeRunner scripts LookPath and Run so the compose checker can be driven
// end-to-end without a real Docker daemon.
type fakeRunner struct {
	present    map[string]bool
	lsJSON     string
	daemonDown bool
}

func (f fakeRunner) LookPath(name string) (string, error) {
	if f.present[name] {
		return "/usr/bin/" + name, nil
	}
	return "", errors.New("not found")
}

func (f fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	switch {
	case name == "docker" && strings.Join(args, " ") == "compose ls --all --format json":
		return []byte(f.lsJSON), nil
	// Checkers probe the daemon before trusting the CLI's presence.
	case name == "docker" && strings.Join(args, " ") == "version --format {{.Server.Version}}":
		if f.daemonDown {
			return nil, errors.New("Cannot connect to the Docker daemon at unix:///var/run/docker.sock")
		}
		return []byte("27.0.3\n"), nil
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

// TestEngineSkipsDockerDomainsWhenDaemonUnreachable is the regression guard
// for the bug that motivated PartialError and the daemon probe: running
// without access to the Docker socket (no sudo, not in the docker group) used
// to leave the CLI on PATH, so Available() said yes, every check quietly found
// nothing, and the domain reported Done. Its axis was then scored a perfect
// 100 — the CVE scan in particular claiming a clean bill of health for a host
// it had never looked at.
//
// The axis must be N/A, not perfect, and the reason must be actionable.
func TestEngineSkipsDockerDomainsWhenDaemonUnreachable(t *testing.T) {
	engine := New(Config{
		Registry: check.NewRegistry(composecheck.New(), cvecheck.New()),
		Runner: fakeRunner{
			present:    map[string]bool{"docker": true, "trivy": true},
			daemonDown: true,
		},
	})
	report := engine.Scan(context.Background(), nil)

	for _, d := range report.Domains {
		if d.State != model.ScanSkipped {
			t.Errorf("%s domain state = %v, want skipped", d.Source, d.State)
		}
		if !strings.Contains(d.Reason, "sudo") {
			t.Errorf("%s reason should tell the user how to fix it, got %q", d.Source, d.Reason)
		}
	}
	for _, ax := range report.Score.Axes {
		if (ax.Source == model.SourceCompose || ax.Source == model.SourceCVE) && ax.Applicable {
			t.Errorf("%s axis must be N/A when the daemon is unreachable, not scored", ax.Source)
		}
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
			name: "CVE image rollup keeps its fix",
			finding: model.NewFinding("cve.outdated-image", "outdated image", model.SeverityHigh,
				model.SourceCVE, model.RemediationReview,
				model.WithService("stack/cache"),
				model.WithMetadata("file", "/tmp/docker-compose.yml"),
				model.WithMetadata("service", "cache"),
				model.WithEvidence("reference", "tag")),
			want: model.RemediationReview,
			why:  "re-pulling a mutable tag is a real remediation the user should see first",
		},
		{
			name: "digest-pinned rollup is demoted to Manual",
			finding: model.NewFinding("cve.outdated-image", "outdated image", model.SeverityHigh,
				model.SourceCVE, model.RemediationManual,
				model.WithService("stack/cache"),
				model.WithMetadata("file", "/tmp/docker-compose.yml"),
				model.WithMetadata("service", "cache"),
				model.WithEvidence("reference", "digest")),
			want: model.RemediationManual,
			why:  "pulling a digest is a no-op, and the builder refuses to build one",
		},
		{
			name: "an individual CVE never resolves to the rollup's fix",
			finding: model.NewFinding("cve.cve-2021-1234", "openssl overflow", model.SeverityHigh,
				model.SourceCVE, model.RemediationReview,
				model.WithService("stack/cache"),
				model.WithMetadata("file", "/tmp/docker-compose.yml"),
				model.WithMetadata("service", "cache")),
			want: model.RemediationManual,
			why:  "the checker no longer emits these, and no builder may ever match one",
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

// tallyRunner counts how many times each command actually reached the host.
type tallyRunner struct {
	mu       sync.Mutex
	calls    map[string]int
	composeF string
}

func (r *tallyRunner) LookPath(string) (string, error) { return "/usr/bin/x", nil }

func (r *tallyRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	joined := name + " " + strings.Join(args, " ")
	r.mu.Lock()
	r.calls[joined]++
	r.mu.Unlock()

	switch {
	case joined == "docker version --format {{.Server.Version}}":
		return []byte("27.0.3\n"), nil
	case joined == "docker compose ls --all --format json":
		return []byte(`[{"Name":"demo","ConfigFiles":"` + r.composeF + `"}]`), nil
	case joined == "docker ps --quiet --no-trunc":
		return []byte(""), nil
	case name == "trivy":
		return []byte(`{"Results":[]}`), nil
	}
	return nil, errors.New("unexpected command: " + joined)
}

func (r *tallyRunner) count(cmd string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[cmd]
}

// TestScanAsksTheHostEachQuestionOnce pins the scan-scoped command cache.
//
// Checkers are read-only and run concurrently, and several independently
// need the same facts: the compose and CVE checkers both enumerate compose
// projects and both inspect the containers Compose did not create, and the
// ports checker re-probes the firewall the firewall checker just probed.
// Each of those ran twice per scan, concurrently — and `docker inspect`
// over every container on a busy host is megabytes of output to fetch and
// parse for the second time.
//
// Deduplicating at the runner rather than in the checkers is what keeps the
// checkers ignorant of each other; this test is what keeps that true.
func TestScanAsksTheHostEachQuestionOnce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "docker-compose.yml")
	yml := "services:\n  cache:\n    image: redis\n    ports:\n      - \"6379:6379\"\n"
	if err := os.WriteFile(path, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}

	r := &tallyRunner{calls: map[string]int{}, composeF: path}
	engine := New(Config{
		// Two checkers that each need the full container inventory.
		Registry: check.NewRegistry(composecheck.New(), cvecheck.New()),
		Store:    history.NewStore(t.TempDir()),
		Runner:   r,
	})
	engine.Scan(context.Background(), nil)

	for _, cmd := range []string{
		"docker compose ls --all --format json",
		"docker ps --quiet --no-trunc",
		"docker version --format {{.Server.Version}}",
	} {
		if n := r.count(cmd); n != 1 {
			t.Errorf("%q ran %d times in one scan, want 1", cmd, n)
		}
	}
}

// The cache belongs to the scan, not the engine. A fix runs commands that
// change the host, and serving one of those from a cache would mean the
// second `ufw allow` of a session silently never happened.
func TestFixCommandsBypassTheScanCache(t *testing.T) {
	r := &tallyRunner{calls: map[string]int{}}
	engine := New(Config{Store: history.NewStore(t.TempDir()), Runner: r})

	for range 3 {
		if _, err := engine.runner.Run(context.Background(), "trivy"); err != nil {
			t.Fatal(err)
		}
	}
	if n := r.count("trivy "); n != 3 {
		t.Errorf("the engine's fix runner ran %d commands, want 3 — it is caching", n)
	}
}
