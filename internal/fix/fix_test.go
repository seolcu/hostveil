package fix

import (
	"slices"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

// representative builds a finding with the metadata/evidence each fix
// builder needs, so the registry can be exercised without a live scan.
func representative(id string) model.Finding {
	f := model.NewFinding(id, "t", model.SeverityHigh, model.SourceCompose, model.RemediationReview,
		model.WithService("app"),
		model.WithMetadata("file", "/tmp/docker-compose.yml"),
		model.WithEvidence("port", "6379"),
		model.WithEvidence("config", "/etc/ssh/sshd_config"),
		model.WithEvidence("mechanism", "dnf-automatic"),
		model.WithEvidence("image", "redis:7"),
		model.WithEvidence("fixable_count", "3"),
		model.WithEvidence("worst_cve", "CVE-2021-1234"),
		model.WithEvidence("reference", "tag"),
	)
	return f
}

// TestEveryRegisteredFixIsValid builds each registered fix from a
// representative finding and asserts it passes Validate — Auto has exactly
// one action, Review has independent alternatives, every edit has a
// Transform, every exec has commands.
// It enumerates the registry itself rather than a hand-kept list, so a new
// registration cannot slip in unvalidated.
func TestEveryRegisteredFixIsValid(t *testing.T) {
	r := Default()
	for _, id := range r.Patterns() {
		// A glob has no single representative finding to build from, so it
		// would silently skip this test's coverage. Nothing registers one
		// today, and the CVE decision depends on that staying true: a
		// "cve.*" pattern would sweep up every per-CVE finding the registry
		// deliberately declines. Make introducing one a visible act.
		if strings.ContainsAny(id, "*?") {
			t.Errorf("glob pattern %q has no representative finding; register an exact ID, or extend this test deliberately", id)
			continue
		}
		f := representative(id)
		fx, ok, err := r.Build(f)
		if err != nil {
			t.Errorf("%s: build error: %v", id, err)
			continue
		}
		if !ok {
			t.Errorf("%s: no fix registered", id)
			continue
		}
		if err := Validate(fx); err != nil {
			t.Errorf("%s: %v", id, err)
		}
		if !fx.Kind.IsFixable() {
			t.Errorf("%s: kind %v is not fixable", id, fx.Kind)
		}
	}
}

func TestRootLoginIsReviewWithAlternatives(t *testing.T) {
	fx, ok, err := Default().Build(representative("ssh.rootlogin"))
	if err != nil || !ok {
		t.Fatalf("build: ok=%v err=%v", ok, err)
	}
	if fx.Kind != model.RemediationReview {
		t.Errorf("rootlogin kind = %v, want Review", fx.Kind)
	}
	if len(fx.Actions) < 2 {
		t.Errorf("review fix should have >= 2 alternatives, has %d", len(fx.Actions))
	}
}

func TestUnregisteredFindingHasNoFix(t *testing.T) {
	_, ok, _ := Default().Build(representative("compose.ds001")) // privileged: Manual, no fix
	if ok {
		t.Error("ds001 should have no registered fix")
	}
}

// TestKnownUnregisteredFindings pins the findings that are fixable in
// principle but deliberately have no builder, each for a reason recorded
// in Default's doc comment. Registering one of these means deleting an
// assertion here, which is the point: the decision should be argued with,
// not quietly reversed.
func TestKnownUnregisteredFindings(t *testing.T) {
	declined := map[string]string{
		"firewall.inactive":       "enabling a default-deny firewall over SSH can lock the user out, and exec fixes have no rollback",
		"ports.exposed-datastore": "the remediation is a bind-address edit in a daemon config whose path and syntax the finding does not carry",
		"ports.exposed-admin":     "same as ports.exposed-datastore",
		"compose.ds016":           "the only honest remediation deletes a mount that Portainer/Traefik/Watchtower legitimately need; :ro is a placebo",
		// vulnFinding builds IDs as "cve."+strings.ToLower(id), so this must
		// be the lowercased form. The entry here used to be the mixed-case
		// "cve.CVE-2023-12345", a string no scan ever emits, which made the
		// assertion pass vacuously.
		"cve.cve-2021-1234": "Trivy's fixed_version is an OS package version, not an image tag — see issue #473",
		"compose.ds009":     "the finding carries no evidence about which UID the image supports, and every candidate is a guess",
		"compose.ds017":     ":ro is the only computable remediation, and Review requires two alternatives",
		"compose.ds001":     "removal-shaped: hostveil cannot tell a needless privileged flag from a load-bearing one",
		"compose.ds005":     "removal-shaped: same, for cap_add",
		"compose.dr001":     "removing host networking without knowing which ports to publish leaves the service unreachable",
		"compose.dr005":     "a two-file change where Action carries one Path, and the real remediation is rotating the leaked secret",
	}
	r := Default()
	for id, why := range declined {
		if r.Has(id) {
			t.Errorf("%s has a registered fix, but is documented as deliberately unfixed: %s", id, why)
		}
	}
}

// TestCVERollupIsFixableButPerCVEIsNot asserts both halves of the CVE
// decision at once, which is the point of having it in one test: a "cve.*"
// glob would satisfy the first assertion and break the second. Per-CVE
// findings stay unfixable because a package version is not an image tag;
// the per-image rollup is fixable because re-pulling a mutable tag needs no
// version mapping at all.
func TestCVERollupIsFixableButPerCVEIsNot(t *testing.T) {
	r := Default()
	if !r.Has("cve.outdated-image") {
		t.Error("the per-image rollup should have a registered fix")
	}
	for _, id := range []string{"cve.cve-2021-1234", "cve.cve-2024-9999"} {
		if r.Has(id) {
			t.Errorf("%s matched a fix; a per-CVE finding must never resolve to one", id)
		}
	}
}

// TestReviewIntentSurvivesAnAutoShapedFix guards the rule that a fix
// registered as Auto describes the fix's shape (one mechanical action) and
// does not overrule a checker that asked for Review. ssh.passwordauth is
// the case that matters: the edit is reversible on disk, but a user
// without a working key loses the session and cannot get back in to roll
// it back, so it must never be swept up by "fix all safe".
func TestReviewIntentSurvivesAnAutoShapedFix(t *testing.T) {
	for _, id := range []string{"ssh.passwordauth", "updates.disabled"} {
		fx, ok, err := Default().Build(representative(id))
		if err != nil || !ok {
			t.Fatalf("%s: build: ok=%v err=%v", id, ok, err)
		}
		// The registry may shape these as Auto; Engine.classify is what holds
		// them at Review. This asserts the registry stays buildable so that
		// resolution has something to work with.
		if !fx.Kind.IsFixable() {
			t.Errorf("%s: kind %v is not fixable", id, fx.Kind)
		}
	}
}

// The two alternatives must be independent choices, not two halves of one
// procedure: action 1 is the zero-downtime option for anyone who cannot
// take an unplanned restart, at the cost of not remediating yet.
func TestRepullFixHasTwoIndependentAlternatives(t *testing.T) {
	fx, ok, err := Default().Build(representative("cve.outdated-image"))
	if err != nil || !ok {
		t.Fatalf("build: ok=%v err=%v", ok, err)
	}
	if fx.Kind != model.RemediationReview {
		t.Errorf("kind = %v, want Review — exec fixes are never Auto", fx.Kind)
	}
	if len(fx.Actions) != 2 {
		t.Fatalf("expected 2 alternatives, got %d", len(fx.Actions))
	}
	if len(fx.Actions[0].Commands) != 2 {
		t.Errorf("pull-and-recreate should be one action of 2 commands, got %d", len(fx.Actions[0].Commands))
	}
	if len(fx.Actions[1].Commands) != 1 {
		t.Errorf("pull-only should be a single command, got %d", len(fx.Actions[1].Commands))
	}
	for i, a := range fx.Actions {
		if a.Kind != ActionExec {
			t.Errorf("action %d is not an exec", i)
		}
		// Exec fixes have no checkpoint; the preview is the only place a
		// user learns that before committing to it.
		if !strings.Contains(a.Warning, "no rollback checkpoint") {
			t.Errorf("action %d warning does not mention the absence of rollback: %q", i, a.Warning)
		}
	}
}

// applyExec runs argv with no shell and no working directory, so a bare
// "docker compose" would resolve against whatever cwd the daemon happened
// to have. Pin the -f.
func TestRepullFixTargetsTheComposeFile(t *testing.T) {
	f := representative("cve.outdated-image")
	fx, _, err := Default().Build(f)
	if err != nil {
		t.Fatal(err)
	}
	for i, a := range fx.Actions {
		for j, cmd := range a.Commands {
			idx := slices.Index(cmd, "-f")
			if idx < 0 || idx+1 >= len(cmd) {
				t.Errorf("action %d command %d has no -f: %v", i, j, cmd)
				continue
			}
			if cmd[idx+1] != f.Metadata["file"] {
				t.Errorf("action %d command %d targets %q, want %q", i, j, cmd[idx+1], f.Metadata["file"])
			}
			if cmd[len(cmd)-1] != f.Service {
				t.Errorf("action %d command %d does not end with the service: %v", i, j, cmd)
			}
		}
	}
}

// A pull on a digest is a no-op by construction. The builder refuses, and a
// build error is how classify learns there is no fix.
func TestRepullRefusesDigestPinnedImages(t *testing.T) {
	f := model.NewFinding("cve.outdated-image", "t", model.SeverityHigh,
		model.SourceCVE, model.RemediationManual,
		model.WithService("app"),
		model.WithMetadata("file", "/tmp/docker-compose.yml"),
		model.WithEvidence("reference", "digest"),
	)
	if _, _, err := Default().Build(f); err == nil {
		t.Error("expected a build error for a digest-pinned image")
	}
}

func TestMemLimitFixOffersSeveralValues(t *testing.T) {
	fx, ok, err := Default().Build(representative("compose.ds010"))
	if err != nil || !ok {
		t.Fatalf("build: ok=%v err=%v", ok, err)
	}
	if fx.Kind != model.RemediationReview {
		t.Errorf("kind = %v, want Review", fx.Kind)
	}
	if len(fx.Actions) < 2 {
		t.Fatalf("expected >= 2 alternatives, got %d", len(fx.Actions))
	}
	in := []byte("services:\n  app:\n    image: myapp\n")
	seen := map[string]bool{}
	for i, a := range fx.Actions {
		out, err := a.Transform(in)
		if err != nil {
			t.Fatalf("action %d: %v", i, err)
		}
		if !strings.Contains(string(out), "mem_limit") {
			t.Errorf("action %d did not set mem_limit: %s", i, out)
		}
		// Each alternative must be a distinct choice, not the same edit
		// relabelled — the loop variable capture bug this guards is easy to
		// reintroduce.
		if seen[string(out)] {
			t.Errorf("action %d produced an output identical to an earlier alternative", i)
		}
		seen[string(out)] = true

		if again, _ := a.Transform(in); string(again) != string(out) {
			t.Errorf("action %d transform is not deterministic", i)
		}
	}
}

func TestExecFixTransformsPure(t *testing.T) {
	// An edit fix's Transform must not touch disk when called; verify it is
	// a pure byte transform.
	fx, _, err := Default().Build(representative("compose.ds006"))
	if err != nil {
		t.Fatal(err)
	}
	in := []byte("services:\n  app:\n    image: myapp\n")
	out, err := fx.Actions[0].Transform(in)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) == string(in) {
		t.Error("transform made no change")
	}
	// Calling again on the same input is deterministic.
	out2, _ := fx.Actions[0].Transform(in)
	if string(out) != string(out2) {
		t.Error("transform is not deterministic")
	}
}
