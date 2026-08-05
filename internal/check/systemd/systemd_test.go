package systemd

import (
	"context"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/check/checktest"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// showArgv is the command the checker runs, spelled once. A fixture that
// scripted a stale copy would not fail — it would fall through to the fake's
// error, which reads as systemd refusing to answer.
var showArgv = []string{"systemctl", "show", "*.service", "--property=" + strings.Join(showProperties, ",")}

// unitRecord renders one record the way `systemctl show` really prints it:
// Key=Value one per line, in an order of systemd's choosing rather than the
// order they were asked for.
func unitRecord(props map[string]string) string {
	// Deliberately not the request order — the parser must key by name.
	order := []string{"FragmentPath", "User", "PrivateTmp", "ProtectHome", "Id", "ProtectSystem", "LoadState", "NoNewPrivileges"}
	var b strings.Builder
	for _, k := range order {
		if v, ok := props[k]; ok {
			b.WriteString(k + "=" + v + "\n")
		}
	}
	return b.String()
}

// operatorUnit is a hand-installed service with every protection off, which
// is what a unit written from a project's README looks like.
func operatorUnit(id string, over map[string]string) string {
	props := map[string]string{
		"Id":              id,
		"LoadState":       "loaded",
		"FragmentPath":    "/etc/systemd/system/" + id,
		"User":            "",
		"NoNewPrivileges": "no",
		"ProtectSystem":   "no",
		"ProtectHome":     "no",
		"PrivateTmp":      "no",
	}
	for k, v := range over {
		props[k] = v
	}
	return unitRecord(props)
}

func scan(t *testing.T, show string) []model.Finding {
	t.Helper()
	r := checktest.New().Script(show, showArgv...)
	fs, err := New().Check(context.Background(), platform.Env{
		ServiceManager: platform.SMSystemd, Runner: r,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if err := f.Validate(); err != nil {
			t.Errorf("%s: invalid finding: %v", f.ID, err)
		}
	}
	return fs
}

func ids(fs []model.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.ID
	}
	return out
}

func find(fs []model.Finding, id, service string) (model.Finding, bool) {
	for _, f := range fs {
		if f.ID == id && f.Service == service {
			return f, true
		}
	}
	return model.Finding{}, false
}

func TestUnhardenedOperatorUnitIsFlagged(t *testing.T) {
	fs := scan(t, operatorUnit("gitea.service", nil))

	for _, want := range []string{
		"systemd.no-new-privileges", "systemd.protect-system",
		"systemd.protect-home", "systemd.private-tmp",
	} {
		f, ok := find(fs, want, "gitea.service")
		if !ok {
			t.Fatalf("expected %s, got %v", want, ids(fs))
		}
		// The unit is what the operator has to open, so it has to be in the
		// evidence and in the instruction.
		if f.Evidence["unit"] != "/etc/systemd/system/gitea.service" {
			t.Errorf("%s: evidence names %q", want, f.Evidence["unit"])
		}
		if !strings.Contains(f.HowToFix, "/etc/systemd/system/gitea.service.d/50-hostveil.conf") {
			t.Errorf("%s: how-to-fix does not name the drop-in:\n%s", want, f.HowToFix)
		}
		if !strings.Contains(f.HowToFix, "systemctl restart gitea.service") {
			t.Errorf("%s: how-to-fix must say the change needs a restart:\n%s", want, f.HowToFix)
		}
		// Manual by decision, and the decision is recorded in fix.Default's
		// register — see TestEveryFindingIsEitherFixableOrDeclinedOnPurpose.
		if f.Remediation != model.RemediationManual {
			t.Errorf("%s: remediation = %v, want Manual", want, f.Remediation)
		}
	}
}

func TestHardenedUnitIsClean(t *testing.T) {
	fs := scan(t, operatorUnit("gitea.service", map[string]string{
		"User":            "gitea",
		"NoNewPrivileges": "yes",
		"ProtectSystem":   "full",
		"ProtectHome":     "yes",
		"PrivateTmp":      "yes",
	}))
	if len(fs) != 0 {
		t.Errorf("a hardened unit produced findings: %v", ids(fs))
	}
}

// The line this domain draws. A distribution hardens its own units on its
// own schedule, and reporting on them would bury the operator's services
// under dozens of findings about software they did not choose to run.
func TestDistributionUnitsAreNotAudited(t *testing.T) {
	show := unitRecord(map[string]string{
		"Id": "sshd.service", "LoadState": "loaded",
		"FragmentPath":  "/usr/lib/systemd/system/sshd.service",
		"User":          "",
		"ProtectSystem": "no", "ProtectHome": "no", "PrivateTmp": "no", "NoNewPrivileges": "no",
	})
	if fs := scan(t, show); len(fs) != 0 {
		t.Errorf("a packaged unit must not be reported: %v", ids(fs))
	}
}

func TestUsrLocalUnitsAreAudited(t *testing.T) {
	show := unitRecord(map[string]string{
		"Id": "app.service", "LoadState": "loaded",
		"FragmentPath":    "/usr/local/lib/systemd/system/app.service",
		"NoNewPrivileges": "no",
	})
	if _, ok := find(scan(t, show), "systemd.no-new-privileges", "app.service"); !ok {
		t.Error("/usr/local/lib/systemd/system is where an operator installs a unit by hand")
	}
}

// A unit systemd could not load has no effective configuration to judge and
// no fragment to point the operator at.
func TestUnloadedUnitsAreSkipped(t *testing.T) {
	show := unitRecord(map[string]string{
		"Id": "gone.service", "LoadState": "not-found",
		"FragmentPath": "", "NoNewPrivileges": "no",
	})
	if fs := scan(t, show); len(fs) != 0 {
		t.Errorf("an unloaded unit must not be reported: %v", ids(fs))
	}
}

// An older systemd that does not implement a property prints nothing for it.
// Nothing is not evidence that the protection is off, and reporting one from
// a silence would be inventing a finding out of a blind spot.
func TestUnknownPropertyIsNotAFinding(t *testing.T) {
	show := unitRecord(map[string]string{
		"Id": "app.service", "LoadState": "loaded",
		"FragmentPath": "/etc/systemd/system/app.service",
		// NoNewPrivileges reported; the other three absent entirely.
		"NoNewPrivileges": "no",
	})
	fs := scan(t, show)
	if len(fs) != 1 || fs[0].ID != "systemd.no-new-privileges" {
		t.Errorf("only the property systemd answered about should be judged, got %v", ids(fs))
	}
}

// Which severity applies depends on the account, and the two rules point in
// opposite directions on purpose: a root service can already do anything, so
// the setuid path NoNewPrivileges closes buys little there, while the
// filesystem protections are worth most exactly there.
func TestSeverityFollowsTheAccount(t *testing.T) {
	asRoot := scan(t, operatorUnit("root.service", nil))
	asUser := scan(t, operatorUnit("user.service", map[string]string{"User": "gitea"}))

	nnpRoot, _ := find(asRoot, "systemd.no-new-privileges", "root.service")
	nnpUser, _ := find(asUser, "systemd.no-new-privileges", "user.service")
	if nnpRoot.Severity != model.SeverityHardening || nnpUser.Severity != model.SeverityWeak {
		t.Errorf("no-new-privileges: root=%v user=%v, want Low and Medium",
			nnpRoot.Severity, nnpUser.Severity)
	}

	sysRoot, _ := find(asRoot, "systemd.protect-system", "root.service")
	sysUser, _ := find(asUser, "systemd.protect-system", "user.service")
	if sysRoot.Severity != model.SeverityWeak || sysUser.Severity != model.SeverityHardening {
		t.Errorf("protect-system: root=%v user=%v, want Medium and Low",
			sysRoot.Severity, sysUser.Severity)
	}

	if got := nnpRoot.Evidence["runs as"]; got != "root (no User= set)" {
		t.Errorf("evidence should say the unit sets no User=, got %q", got)
	}
	if got := nnpUser.Evidence["runs as"]; got != "gitea" {
		t.Errorf("evidence = %q, want the account", got)
	}
}

// Several units in one batched call, separated by blank lines, is the whole
// reason the checker makes one call rather than one per unit.
func TestSeveralUnitsInOneCall(t *testing.T) {
	show := operatorUnit("a.service", map[string]string{"NoNewPrivileges": "yes", "ProtectSystem": "full", "ProtectHome": "yes", "PrivateTmp": "yes"}) +
		"\n" + operatorUnit("b.service", map[string]string{"ProtectSystem": "full", "ProtectHome": "yes", "PrivateTmp": "yes"}) +
		"\n" + unitRecord(map[string]string{"Id": "c.service", "LoadState": "loaded", "FragmentPath": "/usr/lib/systemd/system/c.service", "PrivateTmp": "no"})

	fs := scan(t, show)
	if len(fs) != 1 {
		t.Fatalf("want exactly b.service's one finding, got %v", ids(fs))
	}
	if fs[0].Service != "b.service" || fs[0].ID != "systemd.no-new-privileges" {
		t.Errorf("wrong finding: %s on %s", fs[0].ID, fs[0].Service)
	}
}

// A value may contain "=", and only the first one separates.
func TestParseKeepsEqualsInsideAValue(t *testing.T) {
	us := parseUnits("Id=x.service\nUser=a=b\n")
	if len(us) != 1 || us[0].User != "a=b" {
		t.Errorf("parsed %+v", us)
	}
}

// # Availability
//
// Every one of these is the same invariant: the domain must never let "I
// couldn't look" pass for "nothing there". A skip is scored N/A; a silent
// success on a host that answered nothing would be a perfect axis.
func TestAvailability(t *testing.T) {
	ctx := context.Background()
	c := New()

	// The binary exists on hosts that boot something else, where it exits
	// non-zero with "System has not been booted with systemd".
	up := checktest.New().Script("Version=257\n", "systemctl", "show", "--property=Version")
	if ok, reason := c.Available(ctx, platform.Env{ServiceManager: platform.SMSystemd, Runner: up}); !ok {
		t.Errorf("a systemd host should be available: %q", reason)
	}
	dead := checktest.New() // systemctl present, nothing scripted, so it errors
	ok, reason := c.Available(ctx, platform.Env{ServiceManager: platform.SMSystemd, Runner: dead})
	if ok {
		t.Error("systemctl on PATH is not the same as systemd answering")
	}
	if reason == "" {
		t.Error("a skip needs a reason or the domain reads as unexplained")
	}
	if ok, reason := c.Available(ctx, platform.Env{ServiceManager: platform.SMOpenRC, Runner: up}); ok || reason == "" {
		t.Errorf("a non-systemd host is a clean skip, got ok=%v reason=%q", ok, reason)
	}
	if ok, _ := c.Available(ctx, platform.Env{ServiceManager: platform.SMSystemd, Runner: checktest.New().Only()}); ok {
		t.Error("no systemctl on the host at all is a skip")
	}
}

// A failure to enumerate is an error, not an empty result: the axis is then
// excluded rather than scored a perfect 100 on evidence nobody obtained.
func TestEnumerationFailureIsAnError(t *testing.T) {
	_, err := New().Check(context.Background(), platform.Env{
		ServiceManager: platform.SMSystemd, Runner: checktest.New(),
	})
	if err == nil {
		t.Fatal("a systemctl that would not answer must not read as a host with no units")
	}
}

// The enumerated protections are not booleans, and this is what the check
// against `!on(v)` would have got wrong: ProtectSystem prints
// no/yes/full/strict and ProtectHome prints no/yes/read-only/tmpfs, so
// "strict" and "read-only" are protection *on* and must not be flagged.
//
// The value set comes from a real host: 77 units answered no/yes/full/strict
// for ProtectSystem and nothing else — which is also why neither rule has a
// second arm for "off", a spelling systemd never emits.
func TestEnumeratedProtectionsAreNotBooleans(t *testing.T) {
	for _, tc := range []struct {
		protectSystem, protectHome string
		wantFindings               int
	}{
		{"strict", "read-only", 0},
		{"full", "yes", 0},
		{"yes", "tmpfs", 0},
		{"no", "yes", 1},
		{"strict", "no", 1},
		{"no", "no", 2},
	} {
		show := operatorUnit("app.service", map[string]string{
			// Isolate the two rules under test.
			"NoNewPrivileges": "yes", "PrivateTmp": "yes",
			"ProtectSystem": tc.protectSystem, "ProtectHome": tc.protectHome,
		})
		if fs := scan(t, show); len(fs) != tc.wantFindings {
			t.Errorf("ProtectSystem=%s ProtectHome=%s: got %v, want %d finding(s)",
				tc.protectSystem, tc.protectHome, ids(fs), tc.wantFindings)
		}
	}
}

// realShowOutput is `systemctl show '*.service' --property=...` copied
// verbatim off a running Fedora 44 host, including its own property order —
// which is not the order the checker asks for. That is the whole reason
// parseUnits keys records by name: a parser reading positionally would put
// PrivateTmp's value into NoNewPrivileges' field and be wrong about every
// unit on every host, while still passing any fixture written in request
// order.
const realShowOutput = `Id=chronyd.service
LoadState=loaded
FragmentPath=/usr/lib/systemd/system/chronyd.service
User=chrony
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
NoNewPrivileges=no

Id=accounts-daemon.service
LoadState=loaded
FragmentPath=/usr/lib/systemd/system/accounts-daemon.service
User=
PrivateTmp=no
ProtectHome=no
ProtectSystem=strict
NoNewPrivileges=no
`

func TestParsesRealSystemctlOutput(t *testing.T) {
	us := parseUnits(realShowOutput)
	if len(us) != 2 {
		t.Fatalf("parsed %d units, want 2", len(us))
	}
	if us[0].ID != "chronyd.service" || us[0].User != "chrony" ||
		us[0].ProtectSystem != "strict" || us[0].PrivateTmp != "yes" {
		t.Errorf("first record read wrong: %+v", us[0])
	}
	// The one with no User= is the common case, and root() has to say so.
	if !us[1].root() || us[1].User != "" {
		t.Errorf("an unset User= is root: %+v", us[1])
	}
	if us[0].root() {
		t.Errorf("a unit with User=chrony is not root: %+v", us[0])
	}
	// Both are packaged units, so a stock host reports nothing — the correct
	// answer for a machine whose operator installed no services of their own,
	// not a checker that failed to look.
	c := New()
	for _, u := range us {
		if c.operatorInstalled(u) {
			t.Errorf("%s is a distribution unit", u.ID)
		}
	}
}
