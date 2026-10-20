package fix

import (
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

func originsFinding(patterns ...string) model.Finding {
	return model.NewFinding("updates.origin-excluded", "t", model.SeverityMedium, model.SourceUpdates, model.RemediationReview,
		model.WithEvidence("patterns", strings.Join(patterns, "\n")))
}

func TestAllowOriginsWritesHostveilsOwnDropIn(t *testing.T) {
	fx, err := buildAllowOrigins(originsFinding(
		"origin=Raspberry Pi Foundation,codename=trixie,label=Raspberry Pi Foundation",
		"origin=cloudsmith/caddy/stable,codename=any-version"))
	if err != nil {
		t.Fatal(err)
	}
	if fx.Kind != model.RemediationReview || len(fx.Actions) != 1 || fx.Actions[0].Warning == "" {
		t.Fatalf("want one Review action with a warning, got %+v", fx)
	}
	a := fx.Actions[0]
	if a.Path != allowOriginsPath || !a.CreateIfMissing {
		t.Errorf("path = %q create = %v", a.Path, a.CreateIfMissing)
	}
	out, err := a.Transform(nil)
	if err != nil {
		t.Fatal(err)
	}
	want := "Unattended-Upgrade::Origins-Pattern {\n" +
		"    \"origin=Raspberry Pi Foundation,codename=trixie,label=Raspberry Pi Foundation\";\n" +
		"    \"origin=cloudsmith/caddy/stable,codename=any-version\";\n" +
		"};\n"
	if !strings.HasSuffix(string(out), want) {
		t.Errorf("got:\n%s\nwant to end with:\n%s", out, want)
	}
}

// A second finding adds to the file, and applying the same one again changes
// nothing — the drop-in is Hostveil's, but a later fix must not drop what an
// earlier one allowed.
func TestAllowOriginsMergesAndIsIdempotent(t *testing.T) {
	first, err := addOriginPatterns(nil, []string{"origin=Tailscale,codename=noble,label=Tailscale"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := addOriginPatterns(first, []string{"origin=Docker,codename=noble,label=Docker CE", "origin=Tailscale,codename=noble,label=Tailscale"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(second), "Tailscale\";") != 1 || !strings.Contains(string(second), "Docker CE\";") {
		t.Errorf("merge lost or duplicated a pattern:\n%s", second)
	}
	again, err := addOriginPatterns(second, []string{"origin=Docker,codename=noble,label=Docker CE"})
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(second) {
		t.Errorf("re-applying changed the file:\n%s\nvs\n%s", second, again)
	}
}

func TestAllowOriginsRefusesAPatternThatWouldBreakTheFile(t *testing.T) {
	if _, err := addOriginPatterns(nil, []string{`origin=a";evil`}); err == nil {
		t.Error("a quote inside a pattern was written into apt's config")
	}
	if _, err := buildAllowOrigins(originsFinding()); err == nil {
		t.Error("a finding naming no repositories built a fix")
	}
}
