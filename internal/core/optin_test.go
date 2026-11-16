package core

import (
	"context"
	"testing"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/history"
	"github.com/seolcu/hostveil/internal/model"
)

func forensicFinding() model.Finding {
	return model.NewFinding("forensic.no-remote-log", "No log copy off the host",
		model.SeverityLow, model.SourceForensic, model.RemediationManual)
}

func sshFinding() model.Finding {
	return model.NewFinding("ssh.x11", "X11 forwarding", model.SeverityLow, model.SourceSSH, model.RemediationManual)
}

func optInEngine(t *testing.T, dir string, optIn ...model.Source) *Engine {
	t.Helper()
	return New(Config{
		Registry: check.NewRegistry(
			&stubChecker{src: model.SourceSSH, findings: []model.Finding{sshFinding()}},
			&stubChecker{src: model.SourceForensic, findings: []model.Finding{forensicFinding()}},
		),
		Store: history.NewStore(dir),
		OptIn: optIn,
	})
}

func hasSource(r model.Report, src model.Source) (finding, domain, axis bool) {
	for _, f := range r.Findings {
		finding = finding || f.Source == src
	}
	for _, d := range r.Domains {
		domain = domain || d.Source == src
	}
	for _, a := range r.Score.Axes {
		axis = axis || a.Source == src
	}
	return
}

// An opt-in domain nobody asked for leaves no trace: no findings, no domain
// row, and no N/A axis. A domain that could not run keeps its N/A row; this
// one was never going to run, and saying N/A on every scan is noise.
func TestAnOptInDomainIsLeftOutUnlessAskedFor(t *testing.T) {
	r := optInEngine(t, t.TempDir()).Scan(context.Background(), nil)
	if f, d, a := hasSource(r, model.SourceForensic); f || d || a {
		t.Errorf("unasked forensic domain left a trace: finding=%v domain=%v axis=%v", f, d, a)
	}
	if f, _, _ := hasSource(r, model.SourceSSH); !f {
		t.Error("the default domain should still run")
	}

	r = optInEngine(t, t.TempDir(), model.SourceForensic).Scan(context.Background(), nil)
	if f, d, a := hasSource(r, model.SourceForensic); !f || !d || !a {
		t.Errorf("asked-for forensic domain missing: finding=%v domain=%v axis=%v", f, d, a)
	}
}

func TestOnlyCanNameAnOptInDomainDirectly(t *testing.T) {
	r := optInEngine(t, t.TempDir()).ScanWith(context.Background(), nil,
		ScanOptions{Only: []model.Source{model.SourceForensic}})
	if f, _, _ := hasSource(r, model.SourceForensic); !f {
		t.Error("--only forensic should run the domain without --with")
	}
}

// Turning the domain off between two scans changes nothing on the host, so
// the delta must not announce its findings resolved.
func TestTurningAnOptInDomainOffResolvesNothing(t *testing.T) {
	dir := t.TempDir()
	optInEngine(t, dir, model.SourceForensic).Scan(context.Background(), nil)
	e := optInEngine(t, dir)
	e.Scan(context.Background(), nil)
	if d := e.LastDelta(); len(d.Resolved) != 0 || len(d.New) != 0 {
		t.Errorf("toggling forensic off produced resolved=%v new=%v", d.Resolved, d.New)
	}
}
