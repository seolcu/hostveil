package fix

import (
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

func scanJailFinding(accessLog, errorLog string) model.Finding {
	var opts []model.FindingOption
	if accessLog != "" {
		opts = append(opts, model.WithEvidence("access-log", accessLog))
	}
	if errorLog != "" {
		opts = append(opts, model.WithEvidence("error-log", errorLog))
	}
	return model.NewFinding("proxy.no-scan-jail", "Nothing is watching this proxy for URL/path scanning",
		model.SeverityMedium, model.SourceProxy, model.RemediationReview, opts...)
}

func TestScanJailFixValidatesAsAReviewWithTwoAlternatives(t *testing.T) {
	fx, err := buildEnableScanJail(scanJailFinding("", ""))
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
	fx, err := buildEnableScanJail(scanJailFinding("", ""))
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

// TestScanJailAlwaysStatesAnExplicitBackend pins a bug caught only by
// running a real fail2ban process (not by reading its docs): "auto" prefers
// the systemd journal over a jail's own logpath whenever the filter defines
// a journalmatch, which nginx-botsearch does, and nginx never writes
// request-level entries to the journal. A body with `enabled = true` and no
// `backend` line watches nothing at all, ever — verified by scripting a
// probe past maxretry against a live jail with and without this line, only
// one of which produced a ban.
func TestScanJailAlwaysStatesAnExplicitBackend(t *testing.T) {
	fx, err := buildEnableScanJail(scanJailFinding("", ""))
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range fx.Actions {
		got, err := a.Transform(nil)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(got), "backend = auto") {
			t.Errorf("%s: body has no explicit backend, so fail2ban may silently watch the systemd "+
				"journal instead of the log files and never see a request at all:\n%s", a.Label, got)
		}
	}
}

func TestScanJailLongerAlternativeSetsAWeekLongBantime(t *testing.T) {
	fx, err := buildEnableScanJail(scanJailFinding("", ""))
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
	fx, err := buildEnableScanJail(scanJailFinding("", ""))
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

// TestScanJailAlwaysNamesBothLogFiles pins the other half of the same bug:
// a bare vhost that returns nginx's own 404 for an unmatched path never
// reaches a static-file lookup, so only the access log carries it — the
// error log stays empty. Both must always be named, not just the one
// jail.conf's own default points at.
func TestScanJailAlwaysNamesBothLogFiles(t *testing.T) {
	fx, err := buildEnableScanJail(scanJailFinding("", ""))
	if err != nil {
		t.Fatal(err)
	}
	got, err := fx.Actions[0].Transform(nil)
	if err != nil {
		t.Fatal(err)
	}
	body := string(got)
	if !strings.Contains(body, "%(nginx_access_log)s") {
		t.Errorf("no access-log evidence, so logpath must fall back to fail2ban's own macro:\n%s", body)
	}
	if !strings.Contains(body, "%(nginx_error_log)s") {
		t.Errorf("no error-log evidence, so logpath must fall back to fail2ban's own macro:\n%s", body)
	}
}

func TestScanJailUsesDiscoveredLogPathsOverTheFallback(t *testing.T) {
	fx, err := buildEnableScanJail(scanJailFinding("/srv/logs/nginx-access.log", "/srv/logs/nginx-error.log"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := fx.Actions[0].Transform(nil)
	if err != nil {
		t.Fatal(err)
	}
	body := string(got)
	if !strings.Contains(body, "/srv/logs/nginx-access.log") {
		t.Errorf("a discovered access log must be named explicitly, got:\n%s", body)
	}
	if !strings.Contains(body, "/srv/logs/nginx-error.log") {
		t.Errorf("a discovered error log must be named explicitly, got:\n%s", body)
	}
}

// Confirmed live against a real nginx + fail2ban: this is exactly the
// arrangement a stock Debian/Ubuntu nginx package produces, and the finding
// still records both as evidence even though they match the compiled-in
// defaults — the fix names them anyway, per
// TestScanJailAlwaysStatesAnExplicitBackend's discovery that leaving
// anything to fail2ban's own default resolution is what silently breaks it.
func TestScanJailNamesTheDefaultPathsExplicitlyToo(t *testing.T) {
	fx, err := buildEnableScanJail(scanJailFinding("/var/log/nginx/access.log", "/var/log/nginx/error.log"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := fx.Actions[0].Transform(nil)
	if err != nil {
		t.Fatal(err)
	}
	body := string(got)
	if !strings.Contains(body, "logpath = /var/log/nginx/access.log") {
		t.Errorf("got:\n%s", body)
	}
	if !strings.Contains(body, "/var/log/nginx/error.log") {
		t.Errorf("got:\n%s", body)
	}
}
