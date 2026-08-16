package firewall

import (
	"context"
	"errors"
	"github.com/seolcu/hostveil/internal/platform"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/check/checktest"
)

func countFindings(t *testing.T, r *checktest.Runner) int {
	t.Helper()
	fs, err := New().Check(context.Background(), r.Env())
	if err != nil {
		t.Fatal(err)
	}
	return len(fs)
}

func TestFirewallActiveUFW(t *testing.T) {
	r := checktest.New().Only("ufw").Outputs(map[string]string{"ufw status": "Status: active\n", "ufw status verbose": "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n"})
	if n := countFindings(t, r); n != 0 {
		t.Errorf("active ufw should yield no finding, got %d", n)
	}
}

func TestFirewallInactive(t *testing.T) {
	r := checktest.New().Only("ufw").Outputs(map[string]string{"ufw status": "Status: inactive\n"})
	if n := countFindings(t, r); n != 1 {
		t.Errorf("inactive ufw should yield one finding, got %d", n)
	}
}

func TestFirewallNoneInstalled(t *testing.T) {
	r := checktest.New().Only()
	if n := countFindings(t, r); n != 1 {
		t.Errorf("no firewall installed should yield one finding, got %d", n)
	}
}

func TestFirewallFirewalld(t *testing.T) {
	r := checktest.New().Only("firewall-cmd").Outputs(map[string]string{"firewall-cmd --state": "running\n", "firewall-cmd --get-default-zone": "public\n", "firewall-cmd --zone=public --list-all": "public (active)\n  target: default\n"})
	if n := countFindings(t, r); n != 0 {
		t.Errorf("running firewalld should yield no finding, got %d", n)
	}
}

func TestFirewallNftablesActive(t *testing.T) {
	// A real host firewall: an input base chain that drops by default.
	ruleset := `table inet filter {
	chain input {
		type filter hook input priority 0; policy drop;
		ct state established,related accept
	}
}`
	r := checktest.New().Only("nft").Outputs(map[string]string{"nft list ruleset": ruleset})
	if n := countFindings(t, r); n != 0 {
		t.Errorf("an active input-dropping nftables firewall should yield no finding, got %d", n)
	}
}

// TestFirewallDockerRulesNotCountedAsFirewall is the regression guard for
// the false-negative found by the demo VM: Docker installs nftables tables
// for container networking, but they are NOT a host firewall, so a Docker
// host with no ufw/firewalld must still be flagged.
func TestFirewallDockerRulesNotCountedAsFirewall(t *testing.T) {
	dockerRuleset := `table ip nat {
	chain DOCKER { }
	chain POSTROUTING { type nat hook postrouting priority srcnat; policy accept; }
}
table ip filter {
	chain DOCKER { }
	chain FORWARD { type filter hook forward priority filter; policy accept; }
}`
	r := checktest.New().Only("nft").Outputs(map[string]string{"nft list ruleset": dockerRuleset})
	if n := countFindings(t, r); n != 1 {
		t.Errorf("Docker's nftables tables must not count as a firewall; expected 1 finding, got %d", n)
	}
}

// TestFirewallUnreadableIsNotReportedAsAbsent is the regression guard for a
// false positive: `ufw status` and `nft list ruleset` both need root, and the
// old code treated every probe error as "not active". A non-root scan of a
// properly firewalled host therefore accused it of having no firewall at all —
// a High finding, on the strength of evidence the scan never obtained.
func TestFirewallUnreadableIsNotReportedAsAbsent(t *testing.T) {
	// ufw is installed but refuses to answer (as it does without root): the
	// fake has no scripted output for it, so Run errors.
	r := checktest.New().Only("ufw")

	fs, err := New().Check(context.Background(), r.Env())
	if len(fs) != 0 {
		t.Errorf("unreadable firewall state must not produce a finding, got %v", fs)
	}

	var partial *check.PartialError
	if !errors.As(err, &partial) {
		t.Fatalf("expected a PartialError so the domain reports Degraded, got %v", err)
	}
	if !strings.Contains(partial.Reason, "sudo") {
		t.Errorf("reason should tell the user how to fix it, got %q", partial.Reason)
	}
}

// TestFirewalldDetectedWhenStateGoesToStderr guards the false positive where
// a running firewalld was reported as no firewall at all. Older firewalld
// prints "running" to stderr, and the runner captures stdout only, so the
// text match saw an empty string. Exit status is the stable signal.
func TestFirewalldDetectedWhenStateGoesToStderr(t *testing.T) {
	r := checktest.New().Only("firewall-cmd").Outputs(map[string]string{"firewall-cmd --state": "", "firewall-cmd --get-default-zone": "public\n", "firewall-cmd --zone=public --list-all": "public (active)\n  target: default\n"})
	if n := countFindings(t, r); n != 0 {
		t.Errorf("firewalld running with empty stdout must count as active, got %d findings", n)
	}
}

// TestIptablesOnlyHostIsNotFlagged guards the false positive on a host still
// using iptables-persistent: ufw, firewalld and nft are all absent, but INPUT
// defaults to DROP, so the host is firewalled and must not be accused.
func TestIptablesOnlyHostIsNotFlagged(t *testing.T) {
	r := checktest.New().Only("iptables").Outputs(map[string]string{
		"iptables -S INPUT": "-P INPUT DROP\n-A INPUT -i lo -j ACCEPT\n-A INPUT -p tcp --dport 22 -j ACCEPT\n",
	})
	if n := countFindings(t, r); n != 0 {
		t.Errorf("an iptables INPUT DROP policy is a host firewall, got %d findings", n)
	}
}

// An ACCEPT policy is the opposite: allow rules say nothing about traffic
// that matches none of them, so the host is still open.
func TestIptablesAcceptPolicyIsStillFlagged(t *testing.T) {
	r := checktest.New().Only("iptables").Outputs(map[string]string{
		"iptables -S INPUT": "-P INPUT ACCEPT\n-A INPUT -p tcp --dport 22 -j ACCEPT\n",
	})
	if n := countFindings(t, r); n != 1 {
		t.Errorf("an iptables ACCEPT policy is not a firewall; want 1 finding, got %d", n)
	}
}

// "Cannot tell" and "definitely absent" must stay distinct: a host with no
// firewall tooling at all is still a confident Inactive.
func TestFirewallProbeStatuses(t *testing.T) {
	cases := []struct {
		name string
		r    *checktest.Runner
		want Status
	}{
		{"no tools installed", checktest.New().Only(), StatusInactive},
		{"ufw answers active", checktest.New().Only("ufw").Outputs(map[string]string{"ufw status": "Status: active\n", "ufw status verbose": "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n"}), StatusActive},
		{"ufw answers inactive", checktest.New().Only("ufw").Outputs(map[string]string{"ufw status": "Status: inactive\n"}), StatusInactive},
		{"ufw installed but unreadable", checktest.New().Only("ufw"), StatusUnknown},
		{"one tool unreadable, another confirms active", checktest.New().Only("ufw", "nft").Outputs(map[string]string{"ufw status": "Status: active\n", "ufw status verbose": "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n"}), StatusActive},
		{"firewalld installed but unreadable", checktest.New().Only("firewall-cmd"), StatusUnknown},
		{"iptables answers drop", checktest.New().Only("iptables").Outputs(map[string]string{"iptables -S INPUT": "-P INPUT DROP\n"}), StatusActive},
		{"iptables answers accept", checktest.New().Only("iptables").Outputs(map[string]string{"iptables -S INPUT": "-P INPUT ACCEPT\n"}), StatusInactive},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, _ := Probe(context.Background(), tc.r); got != tc.want {
				t.Errorf("Probe() = %v, want %v", got, tc.want)
			}
		})
	}
}

// Two blind spots are two reasons. Keeping only the first is the failure the
// two container checkers were fixed for.
func TestBothFirewallGapsAreReported(t *testing.T) {
	r := checktest.New().Only("ufw", "docker", "iptables").Docker("27.0.0").Outputs(map[string]string{
		"ufw status": "Status: active\n",
		// Active, but the default policy line is missing — gap one.
		"ufw status verbose": "Status: active\n",
		// A container publishing to the world, so the bypass check runs...
		"docker ps --format {{.Names}}\t{{.Ports}}": "db\t0.0.0.0:5432->5432/tcp\n",
		// ...and `iptables -S DOCKER-USER` is unscripted, so it cannot be
		// read — gap two, on a host where gap one already happened.
	})
	_, err := New().Check(context.Background(), platform.Env{Runner: r})

	var partial *check.PartialError
	if !errors.As(err, &partial) {
		t.Fatalf("want a PartialError, got %v", err)
	}
	if !strings.Contains(partial.Reason, "default inbound policy") {
		t.Errorf("the first gap is missing: %q", partial.Reason)
	}
	if !strings.Contains(partial.Reason, "DOCKER-USER") {
		t.Errorf("the second gap is missing: %q", partial.Reason)
	}
}

// sshd serving on two ports at once is how an operator changes the SSH port
// without locking themselves out: the old and the new both open until the new
// one is proven, then the old is dropped. The evidence has to carry both, or
// the fix allows one and `ufw --force enable` severs the other with no
// checkpoint to undo it.
func TestTheFindingNamesEveryPortSSHDIsListeningOn(t *testing.T) {
	ss := `LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=1,fd=3))
LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=4))
LISTEN 0 128 [::]:22 [::]:* users:(("sshd",pid=1,fd=5))
LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:(("nginx",pid=9,fd=6))
`
	env := checktest.New().Without(ProbedTools...).Listeners(ss).Env()
	fs, err := New().Check(context.Background(), env)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if len(fs) == 0 {
		t.Fatal("a host with no firewall reported nothing")
	}
	// Sorted and deduplicated: the same port on IPv4 and IPv6 is one port,
	// and the order must not churn between scans over one host state.
	if got, want := fs[0].Evidence["ssh_port"], "22,2222"; got != want {
		t.Errorf("ssh_port = %q, want %q", got, want)
	}
}

// A container has no host firewall and never will.
//
// probe knows ufw, firewall-cmd, nft and iptables. None of them is installed
// in a container, so none fails, `unreadable` stays false, and StatusInactive
// becomes "No active host firewall" at the top severity — on a machine where
// there is nothing to install and nothing to enable, because the packet filter
// that decides whether its ports answer belongs to the host and cannot be seen
// from inside.
//
// Verified against bare Fedora and Alpine images before this gate existed:
// both scored the firewall axis 50/100 on that fabricated High.
func TestAContainerIsSkippedRatherThanAccused(t *testing.T) {
	c := New()
	c.InContainer = func() (bool, string) { return true, "this is a container (/.dockerenv)" }

	ok, why := c.Available(context.Background(), platform.Env{})
	if ok {
		t.Fatal("a container must not be audited for a host firewall it cannot have; " +
			"reporting one is hostveil describing its own blindness as a finding")
	}
	for _, want := range []string{"container", "host"} {
		if !strings.Contains(strings.ToLower(why), want) {
			t.Errorf("skip reason does not mention %q, so the operator cannot tell why the "+
				"domain went away:\n  %s", want, why)
		}
	}
}

// And an ordinary host is still audited, which is the point of the gate being
// a gate. A machine that *runs* containers is not a container.
func TestAHostIsStillAudited(t *testing.T) {
	c := New()
	c.InContainer = func() (bool, string) { return false, "" }

	if ok, why := c.Available(context.Background(), platform.Env{}); !ok {
		t.Errorf("Available = false (%q); the absence of a firewall on a host is a finding", why)
	}
}
