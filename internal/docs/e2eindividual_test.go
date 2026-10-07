package docs

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/fix"
)

// scripts/e2e/individual.sh names the fixes it applies on a real host. A name
// that stops matching a registered fix does not fail the script the way it
// should: `hostveil fix` on an unknown ID errors, but a step that only
// asserts a finding is gone would pass vacuously on an ID nobody reports. So
// every finding ID the script mentions must be one the registry can fix.
func TestTheIndividualFixE2ENamesRealFixes(t *testing.T) {
	script := readRepoFile(t, filepath.Join("scripts", "e2e", "individual.sh"))
	re := regexp.MustCompile(`\b(?:` + strings.Join(sourceNames(), "|") + `)\.[a-z0-9][a-z0-9-]*[a-z0-9]\b`)
	var ids []string
	for _, loc := range re.FindAllStringIndex(script, -1) {
		// Part of a host name — download.proxmox.com — not a finding ID.
		if loc[0] > 0 && strings.ContainsRune("./", rune(script[loc[0]-1])) {
			continue
		}
		ids = append(ids, script[loc[0]:loc[1]])
	}
	if len(ids) < 10 {
		t.Fatalf("only %d finding IDs found in the script; the extraction is broken", len(ids))
	}
	r := fix.Default()
	for _, id := range ids {
		// File names share the shape: compose.yaml is a path, not a finding.
		if _, ext, _ := strings.Cut(id, "."); ext == "yaml" || ext == "yml" || ext == "json" || ext == "conf" || ext == "service" {
			continue
		}
		if !r.Has(id) {
			t.Errorf("scripts/e2e/individual.sh applies %s, which has no registered fix", id)
		}
	}
}
