package docs

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The helper promises one stable dashboard address. vagrant-libvirt can bind
// only IPv6 when IPv4 8787 is occupied and still print a successful mapping,
// while auto-correct can silently choose another port. Either leaves the URL
// printed by run.sh pointing at the wrong process.
func TestDemoDashboardPortStaysTruthful(t *testing.T) {
	vf := string(readRepoFile(t, filepath.Join("demo", "Vagrantfile")))
	if !strings.Contains(vf, `guest: 8787, host: 8787, auto_correct: false`) {
		t.Fatal("demo/Vagrantfile must keep guest and host port 8787 fixed and disable silent auto-correction")
	}

	run := string(readRepoFile(t, filepath.Join("demo", "run.sh")))
	preflight := strings.Index(run, "    require_free_web_port\n")
	up := strings.Index(run, "    vagrant up\n")
	if preflight < 0 || up < 0 || preflight > up {
		t.Fatal("demo/run.sh must reject an occupied 8787 before vagrant up starts the VM")
	}
	if !strings.Contains(run, "    clear_stale_forward\n") ||
		!strings.Contains(run, `index($0, " -L *:8787:")`) {
		t.Fatal("demo/run.sh must clear this checkout's stale libvirt SSH port forward before boot")
	}
}

func TestDemoHelperIsValidShell(t *testing.T) {
	path := filepath.Join(repoRoot(t), "demo", "run.sh")
	if out, err := exec.Command("bash", "-n", path).CombinedOutput(); err != nil {
		t.Fatalf("bash -n demo/run.sh: %v\n%s", err, out)
	}
}
