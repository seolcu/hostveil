// The measured host is a claim about the product, so it is checked against
// the product.
//
// scripts/measure/seed.sh puts a throwaway host into the profile the published
// figures were taken on, and demo/provision.sh puts the Vagrant VM into the
// same one. Both write files whose *paths* only mean something because a
// checker looks there, and a path that drifts does not fail: the domain
// reports "nothing found", which is a clean result, on a host seeded to be
// dirty.
//
// That is not hypothetical. An earlier copy of the measurement seeding wrote
// the OpenClaw config to ~/.config/openclaw/config.json — a plausible path,
// and not one internal/check/agent scans. The agent domain came back N/A on a
// host whose description, on the same page, said it ran two agent runtimes.
// Nothing failed, because nothing was comparing the two.
package docs

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/check/agent"
)

// seeders are the scripts that build a host hostveil is then measured or
// demonstrated against.
var seeders = []string{
	filepath.Join("scripts", "measure", "seed.sh"),
	filepath.Join("demo", "provision.sh"),
}

// homeRelWrite finds paths a seeder installs under a home directory. Both
// scripts write them through install(1) with the destination last, either
// under "$SEED_HOME/" or under a literal /home/<user>/.
var homeRelWrite = regexp.MustCompile(`(?:\$SEED_HOME|/home/[a-z_][a-z0-9_-]*|/root)/(\.[^\s"']+)`)

// writesAPath reports whether a line is a command that puts something at a
// path, rather than prose that mentions one. Both scripts explain themselves
// at length, and a comment naming /root/.cache/trivy is not a fixture writing
// an agent config there.
func writesAPath(line string) bool {
	t := strings.TrimSpace(line)
	if t == "" || strings.HasPrefix(t, "#") {
		return false
	}
	if i := strings.Index(t, " #"); i >= 0 {
		t = t[:i]
	}
	for _, verb := range []string{"install ", "mkdir ", "cp ", "chmod ", "chown ", "cat >", "tee "} {
		if strings.Contains(t, verb) {
			return true
		}
	}
	return false
}

// TestSeedersWriteWhereTheAgentCheckerLooks is the pin the ~/.config/openclaw
// bug would have failed.
//
// Every dot-path a seeder installs under a home directory must be one the
// agent runtime table names — a marker, a config, an env file, or a mode rule.
// The reverse is deliberately not required: a fixture is allowed to seed less
// than the checker can read.
func TestSeedersWriteWhereTheAgentCheckerLooks(t *testing.T) {
	known := map[string]bool{}
	for _, rt := range agent.DefaultRuntimes() {
		for _, m := range rt.Markers {
			known[m] = true
		}
		if rt.Config != "" {
			known[rt.Config] = true
		}
		if rt.EnvFile != "" {
			known[rt.EnvFile] = true
		}
		for _, m := range rt.Modes {
			known[m.Rel] = true
		}
	}
	if len(known) == 0 {
		t.Fatal("the agent runtime table named no paths at all, so this test would pass vacuously")
	}

	for _, rel := range seeders {
		body := readRepoFile(t, rel)
		seen := 0
		var writes []string
		for _, line := range strings.Split(body, "\n") {
			if !writesAPath(line) {
				continue
			}
			for _, m := range homeRelWrite.FindAllStringSubmatch(line, -1) {
				writes = append(writes, m[1])
			}
		}
		for _, w := range writes {
			p := strings.TrimSuffix(w, "/")
			// A seeder legitimately creates parent directories the table does
			// not name in their own right; those are covered by the marker or
			// the mode rule beneath them.
			if known[p] {
				seen++
				continue
			}
			covered := false
			for k := range known {
				if strings.HasPrefix(k, p+"/") {
					covered = true
					break
				}
			}
			if covered {
				seen++
				continue
			}
			t.Errorf("%s installs ~/%s, which internal/check/agent does not scan — "+
				"the domain will report nothing found on a host seeded to have a runtime", rel, p)
		}
		if seen == 0 {
			t.Errorf("%s: this test extracted no home-relative agent path at all. Either the "+
				"seeding moved or homeRelWrite stopped matching it; both make this test pass "+
				"while checking nothing", rel)
		}
	}
}

// TestSeedScriptIsExecutableAndGuarded holds the two properties that make it
// safe to publish a destructive script beside an invitation to run it.
func TestSeedScriptIsExecutableAndGuarded(t *testing.T) {
	rel := filepath.Join("scripts", "measure", "seed.sh")
	fi, err := os.Stat(filepath.Join(repoRoot(t), rel))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&0o111 == 0 {
		t.Errorf("%s is not executable, so the documented command does not run", rel)
	}
	body := readRepoFile(t, rel)
	if !strings.Contains(body, "--force") {
		t.Error("seed.sh has no --force, so its refusal to run on a real machine cannot be overridden " +
			"and somebody will delete the check instead")
	}
	for _, want := range []string{"/.dockerenv", "systemd-detect-virt"} {
		if !strings.Contains(body, want) {
			t.Errorf("seed.sh no longer tests for %s; the guard in front of an irreversible "+
				"script is the one thing here that must not quietly weaken", want)
		}
	}
}

// TestTheMeasurementsPageDescribesTheHostTheSeedBuilds keeps the page's
// prose account of the fixture honest. It checks the weaknesses the page
// names out loud, not every line of the script: the page is allowed to
// summarise, but not to describe a host nothing builds.
func TestTheMeasurementsPageDescribesTheHostTheSeedBuilds(t *testing.T) {
	seed := readRepoFile(t, filepath.Join("scripts", "measure", "seed.sh"))
	for _, c := range []struct{ claim, evidence string }{
		{"a second UID 0 account", "useradd -o -u 0"},
		{"a world-readable /etc/shadow", "chmod 0644 /etc/shadow"},
		{"ufw installed and switched off", "ufw --force disable"},
		{"automatic security updates off", "20auto-upgrades"},
		{"a natively installed Redis on every interface", "bind 0.0.0.0"},
		{"an SSH drop-in that outranks the image's", "00-hostveil-demo.conf"},
		{"three compose stacks", "/opt/stacks"},
		{"two AI agent runtimes", ".openclaw"},
	} {
		if !strings.Contains(seed, c.evidence) {
			t.Errorf("the measurements page says the host has %s, and seed.sh no longer does it "+
				"(looked for %q)", c.claim, c.evidence)
		}
	}
}
