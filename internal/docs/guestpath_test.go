package docs

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The docs hand out commands to run *inside* the demo VM, and the path the
// repository appears at in there is decided by one line of the Vagrantfile.
// Nothing connects the two, and the failure is total rather than partial: a
// command naming the wrong directory does not do less, it does nothing.
//
// DEVELOPMENT.md told anyone who wanted to reproduce the published
// measurements to run
//
//	vagrant ssh -c 'sudo /vagrant/scripts/measure/run.sh -c -p seeded out.json'
//
// and there is no /vagrant in that VM — the synced folder is mounted at
// /hostveil. Three commands, one for the harness, one for the control group
// and one for the control run, all of them "No such file or directory". The
// path is Vagrant's own default, which is exactly why it reads as right.
var (
	syncedFolder = regexp.MustCompile(`config\.vm\.synced_folder\s+"\.\.",\s*"([^"]+)"`)
	guestRepoRef = regexp.MustCompile(`(/[A-Za-z0-9_.-]+)/(?:scripts|cmd|internal|demo)/`)
)

func TestDocsNameTheDirectoryTheRepoIsActuallyMountedAt(t *testing.T) {
	vf := readRepoFile(t, filepath.Join("demo", "Vagrantfile"))
	m := syncedFolder.FindStringSubmatch(vf)
	if m == nil {
		t.Fatal("demo/Vagrantfile no longer declares a synced_folder for \"..\"; if the " +
			"repo reaches the VM some other way, this pin needs rewriting with it")
	}
	mount := m[1]

	for _, doc := range []string{
		"AGENTS.md",
		"CONTRIBUTING.md",
		filepath.Join("docs", "DEVELOPMENT.md"),
		filepath.Join("demo", "README.md"),
	} {
		body := readRepoFile(t, doc)
		for line := range strings.SplitSeq(body, "\n") {
			// Only lines that run something in the guest. A prose mention of a
			// host path is not a command anybody pastes.
			if !strings.Contains(line, "vagrant ssh") {
				continue
			}
			for _, ref := range guestRepoRef.FindAllStringSubmatch(line, -1) {
				if ref[1] != mount {
					t.Errorf("%s runs %s inside the VM, where the repo is mounted at %s:\n  %s",
						doc, ref[1], mount, strings.TrimSpace(line))
				}
			}
		}
	}
}
