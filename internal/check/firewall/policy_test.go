package firewall

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// denies is the fixture pair for a correctly-configured front-end, so a
// test about something else does not have to restate it.
func ufwOutputs(defaultLine string) map[string]string {
	return map[string]string{
		"ufw status":         "Status: active\n",
		"ufw status verbose": "Status: active\n" + defaultLine,
	}
}

func firewalldOutputs(target string) map[string]string {
	return map[string]string{
		"firewall-cmd --state":                  "running\n",
		"firewall-cmd --get-default-zone":       "public\n",
		"firewall-cmd --zone=public --list-all": "public (active)\n  target: " + target + "\n  services: ssh dhcpv6-client\n",
	}
}

func checkFindings(t *testing.T, r fakeRunner) ([]model.Finding, error) {
	t.Helper()
	return New().Check(context.Background(), platform.Env{Runner: r})
}

// A firewall that runs and permits is the same posture as no firewall,
// and it used to score the axis a perfect 100 — the third-heaviest axis in
// the model. nftables and iptables were always held to the default-policy
// standard (hasHostFirewall and hasDropPolicy both require a drop or
// reject on the input hook); ufw and firewalld were not.
func TestDefaultAllowIsFlagged(t *testing.T) {
	for _, tc := range []struct {
		name    string
		runner  fakeRunner
		wantHit bool
	}{
		{
			"ufw denying inbound is clean",
			fakeRunner{present: map[string]bool{"ufw": true},
				outputs: ufwOutputs("Default: deny (incoming), allow (outgoing), disabled (routed)\n")},
			false,
		},
		{
			"ufw rejecting inbound is clean",
			fakeRunner{present: map[string]bool{"ufw": true},
				outputs: ufwOutputs("Default: reject (incoming), allow (outgoing), disabled (routed)\n")},
			false,
		},
		{
			"ufw allowing inbound is flagged",
			fakeRunner{present: map[string]bool{"ufw": true},
				outputs: ufwOutputs("Default: allow (incoming), allow (outgoing), disabled (routed)\n")},
			true,
		},
		{
			// Outgoing is allow on essentially every host and denying it is
			// a deliberate, unusual choice. Reading the wrong half of the
			// line would accuse the overwhelming majority of correct
			// configurations.
			"denying inbound while allowing outbound is clean",
			fakeRunner{present: map[string]bool{"ufw": true},
				outputs: ufwOutputs("Default: deny (incoming), allow (outgoing), allow (routed)\n")},
			false,
		},
		{
			"firewalld with the default target is clean",
			fakeRunner{present: map[string]bool{"firewall-cmd": true}, outputs: firewalldOutputs("default")},
			false,
		},
		{
			"firewalld with an explicit DROP target is clean",
			fakeRunner{present: map[string]bool{"firewall-cmd": true}, outputs: firewalldOutputs("DROP")},
			false,
		},
		{
			"firewalld with an ACCEPT target is flagged",
			fakeRunner{present: map[string]bool{"firewall-cmd": true}, outputs: firewalldOutputs("ACCEPT")},
			true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs, err := checkFindings(t, tc.runner)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			got := false
			for _, f := range fs {
				if f.ID == "firewall.default-allow" {
					got = true
				}
			}
			if got != tc.wantHit {
				t.Errorf("firewall.default-allow fired = %v, want %v (findings: %v)", got, tc.wantHit, fs)
			}
		})
	}
}

// The same rule the probe itself follows, and the one this whole domain is
// built on: "I could not look" is not "nothing there". `ufw status
// verbose` needs root, and a non-root scan must degrade the axis rather
// than accuse a host whose policy it never read.
func TestUnreadablePolicyDegradesRatherThanAccuses(t *testing.T) {
	// Active by `ufw status`, but the verbose query is not stubbed, so it
	// errors — exactly what happens without root.
	r := fakeRunner{
		present: map[string]bool{"ufw": true},
		outputs: map[string]string{"ufw status": "Status: active\n"},
	}
	fs, err := checkFindings(t, r)
	for _, f := range fs {
		if f.ID == "firewall.default-allow" {
			t.Error("an unreadable policy produced the finding; it must only degrade")
		}
	}
	var pe *check.PartialError
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v, want a PartialError so the axis is marked degraded", err)
	}
}

// firewalld reached through a zone that cannot be listed is the same case.
func TestUnreadableFirewalldZoneDegrades(t *testing.T) {
	r := fakeRunner{
		present: map[string]bool{"firewall-cmd": true},
		outputs: map[string]string{
			"firewall-cmd --state":            "running\n",
			"firewall-cmd --get-default-zone": "public\n",
			// --list-all is not stubbed: it errors.
		},
	}
	_, err := checkFindings(t, r)
	var pe *check.PartialError
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v, want a PartialError", err)
	}
}

// nftables and iptables are never queried again: probe only reports them
// active after seeing a drop or reject policy, so the question is already
// answered. Asking twice could only produce a different answer by reading
// something else.
func TestNftablesNeedsNoSecondQuery(t *testing.T) {
	r := fakeRunner{
		present: map[string]bool{"nft": true},
		outputs: map[string]string{
			"nft list ruleset": "table inet filter {\n chain input {\n type filter hook input priority 0; policy drop;\n }\n}\n",
		},
	}
	fs, err := checkFindings(t, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("a drop-policy nftables ruleset must be clean, got %v", fs)
	}
}

// The finding must name the front-end it found, because the remediation
// differs entirely: `ufw default deny incoming` versus a firewalld zone
// target. A finding that gave ufw's advice on a firewalld host would be
// worse than none.
func TestDefaultAllowFindingNamesItsFrontEnd(t *testing.T) {
	for which, want := range map[string]string{"ufw": "ufw default deny incoming", "firewalld": "--set-target"} {
		f := defaultAllowFinding(which)
		if f.Evidence["firewall"] != which {
			t.Errorf("%s: evidence names %q", which, f.Evidence["firewall"])
		}
		if !strings.Contains(f.HowToFix, want) {
			t.Errorf("%s: how-to-fix does not carry %q: %s", which, want, f.HowToFix)
		}
		if err := f.Validate(); err != nil {
			t.Errorf("%s: invalid finding: %v", which, err)
		}
	}
}
