package updates

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/check/checktest"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// The fixtures below are cut from real hosts, under LC_ALL=C: a Raspberry Pi
// on Debian trixie, an Ubuntu noble VM with Caddy's own repository, and a
// stock Ubuntu noble laptop.

// uuDump renders what `apt-config dump` prints for the two keys.
func uuDump(patterns, allowed []string) string {
	var b strings.Builder
	b.WriteString(originsPatternKey + " \"\";\n")
	for _, p := range patterns {
		b.WriteString(originsPatternKey + ":: \"" + p + "\";\n")
	}
	if allowed != nil {
		b.WriteString(allowedOriginsKey + " \"\";\n")
		for _, a := range allowed {
			b.WriteString(allowedOriginsKey + ":: \"" + a + "\";\n")
		}
	}
	return b.String()
}

// Debian's 50unattended-upgrades as trixie ships it.
var debianDefaults = []string{
	"origin=Debian,codename=${distro_codename},label=Debian",
	"origin=Debian,codename=${distro_codename},label=Debian-Security",
	"origin=Debian,codename=${distro_codename}-security,label=Debian-Security",
}

// Ubuntu's, which still uses the legacy form.
var ubuntuAllowed = []string{
	"${distro_id}:${distro_codename}",
	"${distro_id}:${distro_codename}-security",
	"${distro_id}ESMApps:${distro_codename}-apps-security",
	"${distro_id}ESM:${distro_codename}-infra-security",
}

const piPolicy = `Package files:
 100 /var/lib/dpkg/status
     release a=now
 500 https://pkgs.tailscale.com/stable/debian trixie/main arm64 Packages
     release o=Tailscale,n=trixie,l=Tailscale,c=main,b=arm64
     origin pkgs.tailscale.com
 500 http://archive.raspberrypi.com/debian trixie/main arm64 Packages
     release o=Raspberry Pi Foundation,a=stable,n=trixie,l=Raspberry Pi Foundation,c=main,b=arm64
     origin archive.raspberrypi.com
 500 http://deb.debian.org/debian-security trixie-security/main arm64 Packages
     release v=13,o=Debian,a=stable-security,n=trixie-security,l=Debian-Security,c=main,b=arm64
     origin deb.debian.org
 500 http://deb.debian.org/debian trixie-updates/main arm64 Packages
     release v=13-updates,o=Debian,a=stable-updates,n=trixie-updates,l=Debian,c=main,b=arm64
     origin deb.debian.org
 500 http://deb.debian.org/debian trixie/main arm64 Packages
     release v=13.7,o=Debian,a=stable,n=trixie,l=Debian,c=main,b=arm64
     origin deb.debian.org
Pinned packages:
`

const piUpgradable = `Listing...
cifs-utils/stable-security 2:7.4-1+deb13u2 arm64 [upgradable from: 2:7.4-1+deb13u1]
libc6/stable 2.41-12+rpt1+deb13u4 arm64 [upgradable from: 2.41-12+rpt1+deb13u2]
linux-image-rpi-v8/stable 1:6.18.50-1+rpt1 arm64 [upgradable from: 1:6.12.75-1+rpt1]
raspi-utils-core/stable 20260626 arm64 [upgradable from: 20260304]
tzdata/stable-updates 2026b-0+deb13u1 all [upgradable from: 2026a-0+deb13u1]
`

const piCandidates = `cifs-utils:
  Installed: 2:7.4-1+deb13u1
  Candidate: 2:7.4-1+deb13u2
  Version table:
     2:7.4-1+deb13u2 500
        500 http://deb.debian.org/debian-security trixie-security/main arm64 Packages
 *** 2:7.4-1+deb13u1 500
        500 http://deb.debian.org/debian trixie/main arm64 Packages
        100 /var/lib/dpkg/status
libc6:
  Installed: 2.41-12+rpt1+deb13u2
  Candidate: 2.41-12+rpt1+deb13u4
  Version table:
     2.41-12+rpt1+deb13u4 500
        500 http://archive.raspberrypi.com/debian trixie/main arm64 Packages
 *** 2.41-12+rpt1+deb13u2 100
        100 /var/lib/dpkg/status
     2.41-12+deb13u4 500
        500 http://deb.debian.org/debian trixie/main arm64 Packages
linux-image-rpi-v8:
  Installed: 1:6.12.75-1+rpt1
  Candidate: 1:6.18.50-1+rpt1
  Version table:
     1:6.18.50-1+rpt1 500
        500 http://archive.raspberrypi.com/debian trixie/main arm64 Packages
 *** 1:6.12.75-1+rpt1 100
        100 /var/lib/dpkg/status
raspi-utils-core:
  Installed: 20260304
  Candidate: 20260626
  Version table:
     20260626 500
        500 http://archive.raspberrypi.com/debian trixie/main arm64 Packages
 *** 20260304 100
        100 /var/lib/dpkg/status
tzdata:
  Installed: 2026a-0+deb13u1
  Candidate: 2026b-0+deb13u1
  Version table:
     2026b-0+deb13u1 500
        500 http://deb.debian.org/debian trixie-updates/main arm64 Packages
 *** 2026a-0+deb13u1 100
        100 /var/lib/dpkg/status
`

var piNames = []string{"cifs-utils", "libc6", "linux-image-rpi-v8", "raspi-utils-core", "tzdata"}

// originsEnv scripts every command the origin question runs.
func originsEnv(distroID, upgradable, dump, policy, candidates string, names ...string) platform.Env {
	r := checktest.New().Outputs(map[string]string{"apt list --upgradable": upgradable})
	r.Script(dump, "apt-config", "dump", originsPatternKey, allowedOriginsKey)
	r.Script(policy, "apt-cache", "policy")
	r.Script(candidates, append([]string{"apt-cache", "policy"}, names...)...)
	return platform.Env{PackageManager: platform.PMApt, DistroID: distroID, Runner: r}
}

// ubuntuOrigins is a stock Ubuntu host whose upgrades all come from the
// distribution, for tests about something else that still reach the origin
// question.
func ubuntuOrigins(upgradable string, names ...string) platform.Env {
	return originsEnv("ubuntu", upgradable, uuDump(nil, ubuntuAllowed), "Package files:\n", "", names...)
}

func codenameChecker(t *testing.T, codename string) *Checker {
	t.Helper()
	c := aptChecker(t, true, false)
	if err := os.WriteFile(c.OSReleasePath, []byte("VERSION_CODENAME="+codename+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return c
}

// The host this finding was written for: unattended-upgrades on, Debian's
// default patterns, and the Pi archive carrying the kernel and libc.
func TestAPiArchiveLeftOutOfUnattendedUpgradesIsReported(t *testing.T) {
	env := originsEnv("debian", piUpgradable, uuDump(debianDefaults, nil), piPolicy, piCandidates, piNames...)
	fs, err := codenameChecker(t, "trixie").Check(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	f := find(t, fs, "updates.origin-excluded")
	if f.Severity != model.SeverityMedium || f.Remediation != model.RemediationReview {
		t.Errorf("severity/remediation = %v/%v, want medium/review", f.Severity, f.Remediation)
	}
	repos := f.Evidence["repositories"]
	if !strings.Contains(repos, "Raspberry Pi Foundation (3: libc6 linux-image-rpi-v8 raspi-utils-core)") {
		t.Errorf("repositories = %q", repos)
	}
	// tzdata waits in Debian's own stable-updates, which the distribution
	// leaves out on purpose; cifs-utils is in -security, which is allowed.
	if strings.Contains(repos, "Debian") {
		t.Errorf("the distribution's own pockets were reported: %q", repos)
	}
	if got, want := f.Evidence["patterns"], "origin=Raspberry Pi Foundation,codename=trixie,label=Raspberry Pi Foundation"; got != want {
		t.Errorf("patterns = %q, want %q", got, want)
	}
	if !strings.Contains(f.Description, "kernel or a core library") {
		t.Error("a kernel and libc waiting should be called out")
	}
	// The count the rest of the domain gives is one — the -security row —
	// which is why this finding exists.
	if p := find(t, fs, "updates.pending-security"); p.Evidence["pending"] != "1" {
		t.Errorf("pending = %q, want 1", p.Evidence["pending"])
	}
}

func TestAllowingTheArchiveClearsIt(t *testing.T) {
	patterns := append(append([]string{}, debianDefaults...),
		"origin=Raspberry Pi Foundation,codename=${distro_codename},label=Raspberry Pi Foundation")
	env := originsEnv("debian", piUpgradable, uuDump(patterns, nil), piPolicy, piCandidates, piNames...)
	fs, err := codenameChecker(t, "trixie").Check(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if f.ID == "updates.origin-excluded" {
			t.Fatalf("allowed archive still reported: %v", f.Evidence)
		}
	}
}

// Caddy's repository is named "cloudsmith/caddy/stable" and labelled
// "source=none". The '/' must not stop a glob, and a label with '=' in it
// cannot go into a pattern unattended-upgrades would parse.
const caddyPolicy = `Package files:
 100 /var/lib/dpkg/status
     release a=now
 500 https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version/main arm64 Packages
     release o=cloudsmith/caddy/stable,a=any-version,n=any-version,l=source=none,c=main,b=arm64
     origin dl.cloudsmith.io
 500 http://ports.ubuntu.com/ubuntu-ports noble-security/universe arm64 Packages
     release v=24.04,o=Ubuntu,a=noble-security,n=noble,l=Ubuntu,c=universe,b=arm64
     origin ports.ubuntu.com
Pinned packages:
`

const caddyUpgradable = `Listing...
caddy/any-version 2.11.7 arm64 [upgradable from: 2.11.6]
`

const caddyCandidates = `caddy:
  Installed: 2.11.6
  Candidate: 2.11.7
  Version table:
     2.11.7 500
        500 https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version/main arm64 Packages
 *** 2.11.6 100
        100 /var/lib/dpkg/status
`

func TestAVendorRepositoryIsReportedWithAPatternUnattendedUpgradesCanParse(t *testing.T) {
	env := originsEnv("ubuntu", caddyUpgradable, uuDump(nil, ubuntuAllowed), caddyPolicy, caddyCandidates, "caddy")
	fs, err := codenameChecker(t, "noble").Check(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	f := find(t, fs, "updates.origin-excluded")
	if got, want := f.Evidence["patterns"], "origin=cloudsmith/caddy/stable,codename=any-version"; got != want {
		t.Errorf("patterns = %q, want %q (no label carrying '=')", got, want)
	}
	if strings.Contains(f.Description, "kernel or a core library") {
		t.Error("caddy is neither the kernel nor a core library")
	}
}

func TestAGlobCrossesSlashesTheWayFnmatchDoes(t *testing.T) {
	env := originsEnv("ubuntu", caddyUpgradable, uuDump([]string{"origin=cloudsmith/*"}, ubuntuAllowed), caddyPolicy, caddyCandidates, "caddy")
	fs, err := codenameChecker(t, "noble").Check(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if f.ID == "updates.origin-excluded" {
			t.Fatalf("origin=cloudsmith/* did not match cloudsmith/caddy/stable")
		}
	}
}

// A stock Ubuntu host with only -updates waiting: Ubuntu leaves that pocket
// out of the default on purpose, so this is not news and must stay quiet.
func TestTheDistributionsOwnUpdatesPocketIsNotReported(t *testing.T) {
	policy := `Package files:
 500 http://kr.archive.ubuntu.com/ubuntu noble-updates/main amd64 Packages
     release v=24.04,o=Ubuntu,a=noble-updates,n=noble,l=Ubuntu,c=main,b=amd64
     origin kr.archive.ubuntu.com
`
	upg := "Listing...\nvim/noble-updates 2:9.1.0016-1ubuntu7.9 amd64 [upgradable from: 2:9.1.0016-1ubuntu7.8]\n"
	cands := `vim:
  Installed: 2:9.1.0016-1ubuntu7.8
  Candidate: 2:9.1.0016-1ubuntu7.9
  Version table:
     2:9.1.0016-1ubuntu7.9 500
        500 http://kr.archive.ubuntu.com/ubuntu noble-updates/main amd64 Packages
 *** 2:9.1.0016-1ubuntu7.8 100
        100 /var/lib/dpkg/status
`
	fs, err := codenameChecker(t, "noble").Check(context.Background(), originsEnv("ubuntu", upg, uuDump(nil, ubuntuAllowed), policy, cands, "vim"))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("want nothing on a stock host, got %v", ids(fs))
	}
}

// The legacy "origin:archive" form allows exactly o=…,a=…, after the same
// substitution.
func TestLegacyAllowedOriginsAreHonoured(t *testing.T) {
	p := uuPatterns(uuDump(nil, []string{"${distro_id}:${distro_codename}-security"}), "Ubuntu", "noble")
	if len(p) != 1 {
		t.Fatalf("patterns = %v", p)
	}
	if !patternMatches(p[0], aptRelease{Origin: "Ubuntu", Archive: "noble-security"}) {
		t.Error("Ubuntu:noble-security did not allow o=Ubuntu,a=noble-security")
	}
	if patternMatches(p[0], aptRelease{Origin: "Ubuntu", Archive: "noble-updates"}) {
		t.Error("Ubuntu:noble-security allowed noble-updates")
	}
}

// A key unattended-upgrades does not know fails its pattern; it does not
// quietly allow everything.
func TestAnUnknownKeyAllowsNothing(t *testing.T) {
	if patternMatches([][2]string{{"o", "Tailscale"}, {"bogus", "x"}}, aptRelease{Origin: "Tailscale"}) {
		t.Error("a pattern with an unknown key matched")
	}
}

// Not being able to ask apt is a gap in the domain, never "nothing excluded",
// and the rest of the domain's answers survive it.
func TestAnUnansweredOriginQuestionDegradesTheDomain(t *testing.T) {
	env := originsEnv("debian", piUpgradable, uuDump(debianDefaults, nil), piPolicy, piCandidates, piNames...)
	env.Runner.(*checktest.Runner).Fail(errors.New("E: Could not open lock file"), "apt-cache", "policy")
	fs, err := codenameChecker(t, "trixie").Check(context.Background(), env)
	var pe *check.PartialError
	if !errors.As(err, &pe) || pe.Covered != 2 || pe.Total != 3 {
		t.Fatalf("err = %v, want a PartialError covering 2 of 3", err)
	}
	find(t, fs, "updates.pending-security")
}

// Without a codename every ${distro_codename} pattern would be compared as
// written and fail, reporting the distribution itself as excluded.
func TestAMissingCodenameIsAGapNotAFinding(t *testing.T) {
	env := originsEnv("debian", piUpgradable, uuDump(debianDefaults, nil), piPolicy, piCandidates, piNames...)
	c := aptChecker(t, true, false)
	c.OSReleasePath = filepath.Join(t.TempDir(), "absent")
	fs, err := c.Check(context.Background(), env)
	var pe *check.PartialError
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v, want a PartialError", err)
	}
	for _, f := range fs {
		if f.ID == "updates.origin-excluded" {
			t.Fatal("reported on a guess")
		}
	}
}

// With unattended-upgrades off, updates.disabled is the whole story and the
// question is not asked at all.
func TestTheQuestionIsNotAskedWhenUnattendedUpgradesIsOff(t *testing.T) {
	c := aptChecker(t, false, false)
	fs, err := c.Check(context.Background(), aptEnv(piUpgradable))
	if err != nil {
		t.Fatalf("err = %v: the origin question ran with the mechanism off", err)
	}
	for _, f := range fs {
		if f.ID == "updates.origin-excluded" {
			t.Fatal("reported with unattended-upgrades off")
		}
	}
}

func TestFnmatch(t *testing.T) {
	for _, tc := range []struct {
		pattern, s string
		want       bool
	}{
		{"Debian", "Debian", true},
		{"Debian", "Debian-Security", false},
		{"Debian*", "Debian-Security", true},
		{"cloudsmith/*", "cloudsmith/caddy/stable", true},
		{"noble-?ecurity", "noble-security", true},
		{"[!a]bc", "xbc", true},
		{"[!a]bc", "abc", false},
		{"a.b", "axb", false},
	} {
		if got := fnmatch(tc.pattern, tc.s); got != tc.want {
			t.Errorf("fnmatch(%q, %q) = %v, want %v", tc.pattern, tc.s, got, tc.want)
		}
	}
}
