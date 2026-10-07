package firewall

import "testing"

const ufwVerbose = `Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
6379/tcp                   DENY IN     Anywhere
5432                       ALLOW IN    10.0.0.0/8
22/tcp                     ALLOW IN    Anywhere
80,443/tcp                 ALLOW IN    Anywhere
6000:6007/tcp              ALLOW IN    Anywhere
6379/tcp (v6)              DENY IN     Anywhere (v6)
22/tcp (v6)                ALLOW IN    Anywhere (v6)
`

func TestUFWBlocksFollowsFirstMatchThenDefault(t *testing.T) {
	v := parseUFWStatus(ufwVerbose)
	if !v.Active || !v.HasRules {
		t.Fatalf("active=%v rules=%v", v.Active, v.HasRules)
	}
	for port, want := range map[int]bool{
		6379:  true,  // denied in both families
		5432:  false, // allowed from a subnet: somebody can reach it
		22:    false,
		443:   false,
		6003:  false,
		27017: true, // no rule, default deny
	} {
		if got := v.Blocks(port); got != want {
			t.Errorf("Blocks(%d) = %v, want %v", port, got, want)
		}
	}
}

func TestUFWWithDefaultAllowBlocksOnlyWhatItDenies(t *testing.T) {
	v := parseUFWStatus("Status: active\nDefault: allow (incoming), allow (outgoing)\n\nTo  Action  From\n--  ------  ----\n3306/tcp  DENY IN  Anywhere\n")
	// The deny covers IPv4 only. IPv6 falls through to the default, which
	// here is allow, so the port is still reachable and must not read as
	// blocked.
	if v.Blocks(3306) {
		t.Error("a v4-only deny under a default of allow leaves v6 open")
	}
	v6 := parseUFWStatus("Status: active\nDefault: allow (incoming), allow (outgoing)\n\nTo  Action  From\n--  ------  ----\n3306/tcp  DENY IN  Anywhere\n3306/tcp (v6)  DENY IN  Anywhere (v6)\n")
	if !v6.Blocks(3306) {
		t.Error("a deny in both families blocks the port")
	}
}

func TestUFWInactiveBlocksNothing(t *testing.T) {
	v := parseUFWStatus("Status: inactive\n")
	if v.Active || v.Blocks(6379) {
		t.Error("an inactive ufw blocks nothing")
	}
}
