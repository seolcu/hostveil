package docs

import (
	"path/filepath"
	"regexp"
	"testing"
)

// scripts/gate.sh is the local copy of CI's gate, so the two tools whose
// versions are pinned in both places must name the same version. A gate that
// lints with a different golangci-lint than CI is the gate that passes while
// CI fails — the outcome the script exists to prevent.
func TestTheLocalGatePinsWhatCIPins(t *testing.T) {
	gate := readRepoFile(t, filepath.Join("scripts", "gate.sh"))
	ci := readRepoFile(t, filepath.Join(".github", "workflows", "ci.yml"))

	local := regexp.MustCompile(`(?m)^LINT_VERSION=(\S+)$`).FindStringSubmatch(gate)
	remote := regexp.MustCompile(`golangci-lint-action@\S+\s+with:\s+version:\s+v(\S+)`).FindStringSubmatch(ci)
	if local == nil || remote == nil {
		t.Fatalf("could not read the golangci-lint version (gate.sh: %v, ci.yml: %v)", local != nil, remote != nil)
	}
	if local[1] != remote[1] {
		t.Errorf("scripts/gate.sh lints with golangci-lint %s; CI uses %s", local[1], remote[1])
	}

	vuln := regexp.MustCompile(`govulncheck@(v[0-9.]+)`)
	g, c := vuln.FindStringSubmatch(gate), vuln.FindStringSubmatch(ci)
	if g == nil || c == nil || g[1] != c[1] {
		t.Errorf("scripts/gate.sh and ci.yml pin different govulncheck versions: %v vs %v", g, c)
	}
}
