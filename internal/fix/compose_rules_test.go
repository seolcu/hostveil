package fix

import "testing"

var composeRuleIDs = []string{
	"compose.ds001", "compose.ds002", "compose.ds003", "compose.ds004", "compose.ds005",
	"compose.ds006", "compose.ds007", "compose.ds008", "compose.ds009", "compose.ds010",
	"compose.ds011", "compose.ds012", "compose.ds013", "compose.ds014", "compose.ds015",
	"compose.ds016", "compose.ds017", "compose.ds018", "compose.ds019",
	"compose.dr001", "compose.dr002", "compose.dr003", "compose.dr004", "compose.dr005",
}

// TestComposeRulesHaveFixes ensures every compose audit rule ID has a
// registered fix so scanner/fix drift is caught in CI.
func TestComposeRulesHaveFixes(t *testing.T) {
	r := New()
	RegisterAll(r)
	for _, id := range composeRuleIDs {
		if r.Lookup(id) == nil {
			t.Errorf("%s has no registered fix", id)
		}
	}
}
