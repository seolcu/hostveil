package core

import (
	"testing"

	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/history"
	"github.com/seolcu/hostveil/internal/model"
)

// registryOf registers one fix under id. Both helpers below build Auto-shaped
// fixes — exactly one action, which is all the shape rule means — so
// buildFix's fix.Validate pass succeeds and the resolution under test is
// reached. A fix that fails Validate is treated as one that failed to build
// and never gets there, which is how a test can look like it pins a
// resolution rule while exercising the fallback.
func registryOf(id string, a fix.Action) *fix.Registry {
	r := fix.NewRegistry()
	r.Register(id, func(model.Finding) (fix.Fix, error) {
		return fix.Fix{Label: "Fix the thing", Kind: model.RemediationAuto, Actions: []fix.Action{a}}, nil
	})
	return r
}

func editAction() fix.Action {
	return fix.Action{
		Label:     "Edit the file",
		Kind:      fix.ActionEdit,
		Path:      "/nonexistent/hostveil-classify-test",
		Transform: func(in []byte) ([]byte, error) { return in, nil },
	}
}

func execAction() fix.Action {
	return fix.Action{
		Label:    "Run the thing",
		Kind:     fix.ActionExec,
		Commands: [][]string{{"true"}},
	}
}

// TestACheckerDeclaringManualIsNotOverruledByTheRegistry pins the direction
// the resolution rule was missing.
//
// "Stricter wins" is stated in classify's own comment, in AGENTS.md, and in
// two checkers that rely on it by name — and it did not hold at the unfixable
// end. A checker declaring Manual was handed straight back to the registry,
// so any fix builder matching the ID overruled the one layer that had looked
// at the host and concluded there was nothing safe to automate.
//
// Both in-tree callers survived it by accident: internal/check/compose forces
// runtime-only container findings to Manual and was saved by the compose
// builders failing to find a file, and internal/fix/compose refuses
// digest-pinned references itself. A builder growing a fallback would have
// turned either into a fix button leading nowhere.
func TestACheckerDeclaringManualIsNotOverruledByTheRegistry(t *testing.T) {
	e := New(Config{Fixes: registryOf("compose.ds016", editAction()), Store: history.NewStore(t.TempDir())})

	findings := []model.Finding{model.NewFinding(
		"compose.ds016", "Port published on all interfaces",
		model.SeverityExposed, model.SourceCompose, model.RemediationManual)}

	e.classify(findings)

	if got := findings[0].Remediation; got != model.RemediationManual {
		t.Fatalf("checker declared Manual, registry shaped Auto, classify said %v — "+
			"the registry decides whether a fix exists, never how much judgment it needs", got)
	}
	if findings[0].IsFixable() {
		t.Error("a finding the checker said cannot be safely automated is offering a fix button")
	}
}

// Unavailable is the same rule at the other unfixable value, and the one with
// a live claimant: a CVE with no upstream patch stays Unavailable even where
// a registered builder would match the ID. Scoring reads it (unavailableRelief
// weights those findings down), so overruling it would move the score too.
func TestUnavailableSurvivesARegisteredFix(t *testing.T) {
	e := New(Config{Fixes: registryOf("cve.outdated-image", editAction()), Store: history.NewStore(t.TempDir())})

	findings := []model.Finding{model.NewFinding(
		"cve.outdated-image", "Image ships known vulnerabilities",
		model.SeverityExposed, model.SourceCVE, model.RemediationUnavailable)}

	e.classify(findings)

	if got := findings[0].Remediation; got != model.RemediationUnavailable {
		t.Fatalf("checker declared Unavailable, classify said %v", got)
	}
}

// A checker with no opinion is the least cautious thing on the scale and
// defers to the registry — the case the old special-cased branch existed to
// serve, which a plain max serves for free because Unset is the zero value.
func TestAnUnsetCheckerDefersToTheRegistry(t *testing.T) {
	e := New(Config{Fixes: registryOf("ssh.rootlogin", editAction()), Store: history.NewStore(t.TempDir())})

	findings := []model.Finding{{
		ID: "ssh.rootlogin", Title: "t",
		Severity: model.SeverityExposed, Source: model.SourceSSH,
	}}

	e.classify(findings)

	if got := findings[0].Remediation; got != model.RemediationAuto {
		t.Fatalf("a checker that declared nothing got %v, not the registry's Auto", got)
	}
}

// TestPreviewReportsTheSameKindTheFindingCarries is the contradiction
// PreviewFix was producing on its own.
//
// It applied the checker-versus-registry half of the resolution and not the
// exec floor, so an exec fix a finding correctly carried as Review previewed
// as "Auto-fix" — on exactly the fixes where "safe to apply unattended" is
// the claim being ruled out. A user reading the preview was told the opposite
// of what the list said, with no way to tell which was right.
func TestPreviewReportsTheSameKindTheFindingCarries(t *testing.T) {
	e := New(Config{Fixes: registryOf("updates.disabled", execAction()), Store: history.NewStore(t.TempDir())})

	findings := []model.Finding{model.NewFinding(
		"updates.disabled", "Automatic security updates are not enabled",
		model.SeverityWeak, model.SourceUpdates, model.RemediationAuto)}
	e.classify(findings)

	p, err := e.PreviewFix(findings[0])
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if p.Kind != findings[0].Remediation {
		t.Errorf("finding is %v but its preview says %v", findings[0].Remediation, p.Kind)
	}
	if p.Kind == model.RemediationAuto {
		t.Error("a preview of a command that cannot be rolled back is labelled Auto-fix")
	}
}
