package fix

import (
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

func scanJailFinding(errorLog string) model.Finding {
	opts := []model.FindingOption{}
	if errorLog != "" {
		opts = append(opts, model.WithEvidence("error-log", errorLog))
	}
	return model.NewFinding("proxy.no-scan-jail", "Nothing is watching this proxy for URL/path scanning",
		model.SeverityMedium, model.SourceProxy, model.RemediationReview, opts...)
}

func TestScanJailFixValidatesAsAReviewWithTwoAlternatives(t *testing.T) {
	fx, err := buildEnableScanJail(scanJailFinding(""))
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(fx); err != nil {
		t.Fatalf("fix does not validate: %v", err)
	}
	if fx.Kind != model.RemediationReview {
		t.Errorf("kind = %v, want Review", fx.Kind)
	}
	if len(fx.Actions) != 2 {
		t.Fatalf("want exactly 2 alternatives, got %d", len(fx.Actions))
	}
}

func TestScanJailDefaultActionEnablesTheJailWithNoBantimeOverride(t *testing.T) {
	fx, err := buildEnableScanJail(scanJailFinding(""))
	if err != nil {
		t.Fatal(err)
	}
	a := fx.Actions[0]
	if a.Kind != ActionEdit {
		t.Fatalf("kind = %v, want ActionEdit", a.Kind)
	}
	if a.Path != scanJailPath {
		t.Errorf("path = %q, want %q", a.Path, scanJailPath)
	}
	if !a.CreateIfMissing {
		t.Error("the drop-in does not exist yet by definition")
	}
	if a.TakesEffectOn == "" {
		t.Error("writing the file is not the same as fail2ban acting on it — TakesEffectOn must say so")
	}

	got, err := a.Transform(nil)
	if err != nil {
		t.Fatal(err)
	}
	body := string(got)
	if !strings.Contains(body, "[nginx-botsearch]") {
		t.Fatalf("body does not enable the jail:\n%s", body)
	}
	if !strings.Contains(body, "enabled = true") {
		t.Fatalf("body does not enable the jail:\n%s", body)
	}
	if strings.Contains(body, "bantime") {
		t.Errorf("the recommended alternative should rely on fail2ban's own default bantime:\n%s", body)
	}
}

func TestScanJailLongerAlternativeSetsAWeekLongBantime(t *testing.T) {
	fx, err := buildEnableScanJail(scanJailFinding(""))
	if err != nil {
		t.Fatal(err)
	}
	got, err := fx.Actions[1].Transform(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "bantime = 1w") {
		t.Errorf("the longer alternative must set bantime = 1w, got:\n%s", got)
	}
}

func TestScanJailTransformIsIdempotent(t *testing.T) {
	fx, err := buildEnableScanJail(scanJailFinding(""))
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range fx.Actions {
		first, err := a.Transform(nil)
		if err != nil {
			t.Fatal(err)
		}
		second, err := a.Transform(first)
		if err != nil {
			t.Fatal(err)
		}
		if string(first) != string(second) {
			t.Errorf("%s: re-running Transform on its own output changed it:\nfirst:\n%s\nsecond:\n%s",
				a.Label, first, second)
		}
	}
}

func TestScanJailOverridesLogpathOnlyForACustomErrorLog(t *testing.T) {
	fx, err := buildEnableScanJail(scanJailFinding("/srv/logs/nginx-error.log"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := fx.Actions[0].Transform(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "logpath = /srv/logs/nginx-error.log") {
		t.Errorf("a custom error log must be named explicitly, got:\n%s", got)
	}
}

func TestScanJailOmitsLogpathForTheCompiledInDefault(t *testing.T) {
	fx, err := buildEnableScanJail(scanJailFinding("/var/log/nginx/error.log"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := fx.Actions[0].Transform(nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "logpath") {
		t.Errorf("fail2ban's own packaged paths already resolve to the compiled-in default; "+
			"writing it out again is unnecessary, got:\n%s", got)
	}
}
