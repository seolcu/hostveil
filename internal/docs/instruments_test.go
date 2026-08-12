package docs

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The measurement harness exists to check hostveil against auditors that have
// never heard of it, and the whole value of that is in the numbers being
// somebody else's. An auditor that did not run has to say so, because the
// alternative is the shape of a clean result: `hardening_index: null,
// warnings: 0, suggestions: 0` is what Lynis emits on a host where Lynis is
// not installed and also what it would emit for a host it had nothing to say
// about.
//
// That is the same rule the scanner itself is built on — a checker must never
// let "I couldn't look" pass for "nothing there" — applied to the thing that
// audits the scanner. It was not being followed: `lynis.sh` swallowed the
// missing binary with `|| true` and the missing report with `except
// FileNotFoundError: pass`, and printed the zeros. I ran the documented
// command on the demo VM, which has neither auditor, and got a measurement
// two thirds of which was silence dressed as a pass.
//
// Run rather than read. A test that grepped for the word "error" would pass on
// a guard placed after the tool is invoked, or on one whose branch cannot be
// reached; these strip the environment the instrument needs and require the
// JSON on stdout to say what is missing.
func TestAnInstrumentWithoutItsToolSaysSoRatherThanReportingZero(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash; these instruments are bash scripts")
	}
	root := repoRoot(t)

	for _, tc := range []struct {
		script string
		env    []string // the environment that makes the tool unfindable
		skipIf string   // a binary whose presence would run the real audit
	}{
		{
			// Nothing is stripped: the ordinary environment is already one
			// without lynis, here and on every CI runner, which is the case
			// this is about. Where lynis *is* installed there is nothing to
			// assert without running a full system audit, so it steps aside.
			script: "lynis.sh",
			env:    []string{"PATH=" + os.Getenv("PATH")},
			skipIf: "lynis",
		},
		{
			// It looks for a checkout rather than a binary, so point it at one
			// that is not there.
			script: "dockerbench.sh",
			env:    []string{"PATH=" + os.Getenv("PATH"), "DOCKER_BENCH_DIR=" + filepath.Join(t.TempDir(), "absent")},
		},
	} {
		if tc.skipIf != "" {
			if _, err := exec.LookPath(tc.skipIf); err == nil {
				t.Logf("%s: %s is installed here, so the missing-tool path cannot be "+
					"exercised without running a real audit", tc.script, tc.skipIf)
				continue
			}
		}
		path := filepath.Join(root, "scripts", "measure", "instruments", tc.script)
		cmd := exec.Command(bash, path)
		cmd.Env = tc.env
		out, err := cmd.Output()
		if err != nil {
			t.Errorf("%s with its tool missing exited %v; an instrument that cannot "+
				"measure still has to produce a reading the harness can record",
				tc.script, err)
			continue
		}

		var got map[string]any
		if err := json.Unmarshal(out, &got); err != nil {
			t.Errorf("%s printed %q, which is not JSON; every phase of the harness "+
				"json.loads this", tc.script, out)
			continue
		}
		if _, ok := got["error"]; !ok {
			t.Errorf("%s reported %v with its tool missing, and nothing in that says "+
				"the tool is missing — a reader takes it for a host with nothing "+
				"wrong", tc.script, got)
		}
	}
}
