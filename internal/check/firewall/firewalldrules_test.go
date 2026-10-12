package firewall

import (
	"context"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/check/checktest"
)

// Captured from a real Fedora 44 (firewalld 2.4.4), LC_ALL=C.
const fedoraPublic = `public (default, active)
  target: default
  ingress-priority: 0
  egress-priority: 0
  icmp-block-inversion: no
  interfaces: ens3
  sources: 
  services: dhcpv6-client mdns ssh
  ports: 
  protocols: 
  forward: yes
  masquerade: no
  forward-ports: 
  source-ports: 
  icmp-blocks: 
  rich rules: 
`

const fedoraActiveZones = `docker
  interfaces: docker0
public (default)
  interfaces: ens3
`

func firewalldRunner(listAll string) *checktest.Runner {
	return checktest.New().Outputs(map[string]string{
		"firewall-cmd --state":                      "running\n",
		"firewall-cmd --get-default-zone":           "public\n",
		"firewall-cmd --zone=public --list-all":     listAll,
		"firewall-cmd --get-active-zones":           fedoraActiveZones,
		"firewall-cmd --info-service=ssh":           "ssh\n  ports: 22/tcp\n  protocols: \n  source-ports: \n  modules: \n  destination: \n  includes: \n  helpers: \n",
		"firewall-cmd --info-service=mdns":          "mdns\n  ports: 5353/udp\n  protocols: \n  source-ports: \n  includes: \n",
		"firewall-cmd --info-service=dhcpv6-client": "dhcpv6-client\n  ports: 546/udp\n  protocols: \n  source-ports: \n  includes: \n",
	})
}

func TestFedoraDefaultZoneBlocksWhatItDoesNotOpen(t *testing.T) {
	v := ReadFirewalld(context.Background(), firewalldRunner(fedoraPublic))
	if !v.Active || v.Zone != "public" {
		t.Fatalf("view = %+v", v)
	}
	for port, want := range map[int]bool{6379: true, 5432: true, 22: false} {
		if got := v.Blocks(port); got != want {
			t.Errorf("Blocks(%d) = %v, want %v", port, got, want)
		}
	}
}

// The fix's own rule, as firewalld lists it, beats an open port: on the real
// host the port answered from outside before the rule and not after.
func TestANegativePriorityRejectBeatsAnOpenPort(t *testing.T) {
	out := strings.Replace(fedoraPublic, "  ports: \n", "  ports: 6379/tcp 9000-9010/tcp\n", 1)
	if v := ReadFirewalld(context.Background(), firewalldRunner(out)); v.Blocks(6379) || v.Blocks(9005) {
		t.Fatal("ports opened by the zone read as blocked")
	}
	out = strings.Replace(out, "  rich rules: \n", "  rich rules: \n\trule priority=\"-100\" port port=\"6379\" protocol=\"tcp\" reject\n", 1)
	v := ReadFirewalld(context.Background(), firewalldRunner(out))
	if !v.Blocks(6379) {
		t.Error("a priority -100 reject does not close the port")
	}
	if v.Blocks(9005) {
		t.Error("the reject closed a port it does not name")
	}
}

func TestAnAcceptingTargetBlocksNothing(t *testing.T) {
	out := strings.Replace(fedoraPublic, "target: default", "target: ACCEPT", 1)
	if ReadFirewalld(context.Background(), firewalldRunner(out)).Blocks(6379) {
		t.Error("a zone that accepts by default blocked a port")
	}
}

// Anything this does not read can open a port, so it is never "blocked".
func TestWhatItCannotReadIsNeverBlocked(t *testing.T) {
	for name, out := range map[string]string{
		"source":         strings.Replace(fedoraPublic, "  sources: \n", "  sources: 10.0.0.0/8\n", 1),
		"forward port":   strings.Replace(fedoraPublic, "  forward-ports: \n", "  forward-ports: port=80:proto=tcp:toport=6379:toaddr=\n", 1),
		"source port":    strings.Replace(fedoraPublic, "  source-ports: \n", "  source-ports: 53/tcp\n", 1),
		"protocol":       strings.Replace(fedoraPublic, "  protocols: \n", "  protocols: tcp\n", 1),
		"complex rich":   strings.Replace(fedoraPublic, "  rich rules: \n", "  rich rules: \n\trule family=\"ipv4\" source address=\"10.0.0.0/8\" port port=\"6379\" protocol=\"tcp\" accept\n", 1),
		"v4-only reject": strings.Replace(fedoraPublic, "  rich rules: \n", "  rich rules: \n\trule family=\"ipv4\" priority=\"-1\" port port=\"5432\" protocol=\"tcp\" reject\n", 1),
	} {
		v := ReadFirewalld(context.Background(), firewalldRunner(out))
		if v.Blocks(6379) || v.Blocks(5432) {
			t.Errorf("%s: read as blocked", name)
		}
	}
}

func TestAnotherActiveZoneIsUnclear(t *testing.T) {
	r := firewalldRunner(fedoraPublic).Script(fedoraActiveZones+"trusted\n  interfaces: eth1\n", "firewall-cmd", "--get-active-zones")
	if ReadFirewalld(context.Background(), r).Blocks(6379) {
		t.Error("traffic on an interface in another zone was judged by the default zone")
	}
}

func TestAStoppedFirewalldBlocksNothing(t *testing.T) {
	r := firewalldRunner(fedoraPublic).Fail(checktest.ExitStatus(252), "firewall-cmd", "--state")
	if v := ReadFirewalld(context.Background(), r); v.Active || v.Blocks(6379) {
		t.Errorf("view = %+v", v)
	}
}

// firewall-cmd exits 252 when firewalld is not running, as root or not.
// That is an answer: the host has no firewall running, and with nothing else
// filtering that is firewall.inactive, not "cannot read firewall state".
func TestAStoppedFirewalldIsInactiveNotUnknown(t *testing.T) {
	r := checktest.New().Only("firewall-cmd").Fail(checktest.ExitStatus(252), "firewall-cmd", "--state")
	if st, _ := Probe(context.Background(), r); st != StatusInactive {
		t.Errorf("status = %v, want inactive", st)
	}
	r = checktest.New().Only("firewall-cmd").Fail(checktest.ExitStatus(253), "firewall-cmd", "--state")
	if st, _ := Probe(context.Background(), r); st != StatusUnknown {
		t.Errorf("not authorized: status = %v, want unknown", st)
	}
}
