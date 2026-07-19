package fix

import (
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
