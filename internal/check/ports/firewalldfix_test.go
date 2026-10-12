package ports

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/check/checktest"
	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// The default zone of a real Fedora 44, LC_ALL=C, with the ports line and
// the rich rules filled in by the test.
const fedoraZone = `public (default, active)
  target: default
  icmp-block-inversion: no
  interfaces: ens3
  sources: 
  services: ssh
  ports: %PORTS%
  protocols: 
  forward: yes
  masquerade: no
  forward-ports: 
  source-ports: 
  icmp-blocks: 
  rich rules: 
%RICH%`

func withFirewalld(ports, rich string) platform.Env {
	zone := strings.NewReplacer("%PORTS%", ports, "%RICH%", rich).Replace(fedoraZone)
	return checktest.New().Without("ufw").Listeners(postgresListening).Outputs(map[string]string{
		"firewall-cmd --state":                  "running\n",
		"firewall-cmd --get-default-zone":       "public\n",
		"firewall-cmd --zone=public --list-all": zone,
		"firewall-cmd --get-active-zones":       "docker\n  interfaces: docker0\npublic (default)\n  interfaces: ens3\n",
		"firewall-cmd --info-service=ssh":       "ssh\n  ports: 22/tcp\n  protocols: \n  source-ports: \n  includes: \n",
	}).Env()
}

// On the real host this was the false positive: firewalld's default zone
// rejected Redis's port, and the scan still called it reachable from the
// network and said to enable ufw.
func TestAPortFirewalldRefusesIsNotReported(t *testing.T) {
	fs, err := New().Check(context.Background(), withFirewalld("", ""))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findByID(fs, "ports.exposed-datastore"); ok {
		t.Error("a port firewalld's default zone rejects is reported reachable")
	}
}

// The loop for the firewalld fix: the zone opens Postgres, the finding names
// firewalld and the zone, the fix adds a priority -100 reject, and the
// checker reading the rule back no longer reports the port.
func TestTheFirewalldRejectClosesTheDatastoreFinding(t *testing.T) {
	fs, err := New().Check(context.Background(), withFirewalld("5432/tcp", ""))
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findByID(fs, "ports.exposed-datastore")
	if !ok {
		t.Fatalf("an opened port was not flagged: %v", fs)
	}
	if f.Remediation != model.RemediationReview || f.Evidence["firewall"] != "firewalld" || f.Evidence["zone"] != "public" {
		t.Fatalf("remediation %v, evidence %v", f.Remediation, f.Evidence)
	}
	fx, ok, err := fix.Default().Build(f)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	if !fx.IndividualOnly {
		t.Error("closing a port is offered one at a time, as on ufw")
	}
	rule := `rule priority="-100" port port="5432" protocol="tcp" reject`
	want := [][]string{
		{"firewall-cmd", "--zone=public", "--add-rich-rule=" + rule},
		{"firewall-cmd", "--permanent", "--zone=public", "--add-rich-rule=" + rule},
	}
	got := fx.Actions[0].Commands
	if len(got) != 2 || !slices.Equal(got[0], want[0]) || !slices.Equal(got[1], want[1]) {
		t.Errorf("runs %q, want %q", got, want)
	}

	fs, err = New().Check(context.Background(), withFirewalld("5432/tcp", "\t"+rule+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, still := findByID(fs, "ports.exposed-datastore"); still {
		t.Error("the port is still reported after the fix's own rule")
	}
}

func TestWithNeitherFirewallTheFindingNamesBoth(t *testing.T) {
	fs, err := New().Check(context.Background(), platform.Env{Runner: noFirewall(postgresListening)})
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findByID(fs, "ports.exposed-datastore")
	if !ok {
		t.Fatal("not flagged")
	}
	if f.Remediation != model.RemediationManual || !strings.Contains(f.WhyNoFix, "firewalld") {
		t.Errorf("remediation %v, why %q", f.Remediation, f.WhyNoFix)
	}
}
