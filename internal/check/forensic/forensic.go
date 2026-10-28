// Package forensic audits forensic readiness: whether this host keeps the
// evidence an investigation would need if something went wrong.
//
// Every other domain asks whether an attacker can get in. This one asks a
// question the operator meets only afterwards — "was I broken into?" — and
// whether the host will be able to answer it. A self-hosted server usually
// cannot, and not because the evidence was destroyed: it was never written.
// The journal lives in memory and is gone at the next reboot, a web server
// runs PHP as www-data and nothing records what www-data executed, the access
// log keeps a week, and the request that carried an exploit looks, in the
// log, exactly like the thousands of scans around it because the log does not
// record its size.
//
// None of these is a way in, so every finding here is Low: the severity scale
// measures how urgently something can be used against the host, and a
// missing log cannot be. What they cost is the ability to tell an attempt
// from a compromise later, which is why the domain exists at all and why its
// cap is small rather than zero.
//
// The checks are deliberately limited to settings with one defensible value
// on a single self-hosted server. Retention targets are ninety days, the
// window in which most intrusions are noticed by someone other than the
// attacker; anything shorter means "last month" is already unanswerable.
package forensic

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// retentionDays is the evidence window every retention check measures
// against. See the package comment for why it is ninety.
const retentionDays = 90

// Checker reports gaps in what this host records for a later investigation.
type Checker struct {
	// Root is prepended to every file path read directly; overridable for
	// tests. Commands are not affected — they go through the runner.
	Root string
}

// New returns a forensic-readiness checker reading the real filesystem.
func New() *Checker { return &Checker{Root: "/"} }

// Source identifies the forensic-readiness domain.
func (*Checker) Source() model.Source { return model.SourceForensic }

// Available requires a Linux host. Each check gates itself on the tool it
// needs, because a host with no auditd is a finding of this domain, not a
// reason to skip it.
func (c *Checker) Available(_ context.Context, _ platform.Env) (bool, string) {
	if ok, why := platform.AuditableOS(); !ok {
		return false, why
	}
	return true, ""
}

// Check runs every readiness check. A check whose tool did not answer is a
// coverage gap, reported as partial rather than as a clean result.
func (c *Checker) Check(ctx context.Context, env platform.Env) ([]model.Finding, error) {
	var (
		findings []model.Finding
		gaps     []string
		total    int
	)
	run := func(name string, fn func() ([]model.Finding, bool)) {
		total++
		fs, ok := fn()
		findings = append(findings, fs...)
		if !ok {
			gaps = append(gaps, name)
		}
	}
	run("journald", func() ([]model.Finding, bool) { return c.checkJournald(ctx, env) })
	run("audit", func() ([]model.Finding, bool) { return c.checkAudit(ctx, env) })
	run("time sync", func() ([]model.Finding, bool) { return c.checkTimeSync(ctx, env) })
	run("logrotate", func() ([]model.Finding, bool) { return c.checkLogrotate() })
	run("web logs", func() ([]model.Finding, bool) { return c.checkWebLogs() })
	run("remote logging", func() ([]model.Finding, bool) { return c.checkRemoteLog(ctx, env) })

	if len(gaps) > 0 {
		return findings, &check.PartialError{
			Reason:  "could not read " + strings.Join(gaps, ", "),
			Covered: total - len(gaps),
			Total:   total,
		}
	}
	return findings, nil
}

// path resolves an absolute host path under Root.
func (c *Checker) path(p string) string { return filepath.Join(c.Root, p) }

// read returns a file's contents, or ok=false when it is absent or
// unreadable. Callers decide which of those is a gap.
func (c *Checker) read(p string) (string, bool) {
	b, err := os.ReadFile(c.path(p))
	if err != nil {
		return "", false
	}
	return string(b), true
}

// exists reports whether a host path exists.
func (c *Checker) exists(p string) bool {
	_, err := os.Stat(c.path(p))
	return err == nil
}
