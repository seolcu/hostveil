package main

import "testing"

func TestNeedsRoot(t *testing.T) {
	cases := map[string]bool{
		"scan":      true,
		"tui":       true,
		"fix":       true,
		"serve":     true,
		"web":       true,
		"explain":   true,
		"rollback":  true,
		"history":   true,
		"update":    true,
		"uninstall": true,
		"version":   false,
		"help":      false,
		"":          false,
		"bogus":     false,
	}
	for cmd, want := range cases {
		if got := needsRoot(cmd); got != want {
			t.Errorf("needsRoot(%q) = %v, want %v", cmd, got, want)
		}
	}
}

// The guard this replaced could not fire. It passed HOSTVEIL_ELEVATED=1 to the
// child through syscall.Exec's environment, and sudo's env_reset — the default
// everywhere — drops any variable env_keep does not name. Confirmed on Debian
// 13: the child sees it empty.
//
// So the scenario its own comment named, sudo running without yielding root,
// was an unbounded chain of sudo invocations rather than one attempt and a
// graceful fall back to an unprivileged scan.
func TestAlreadyElevatedFiresOnWhatSudoActuallySets(t *testing.T) {
	// SUDO_USER is set by sudo in the target environment, and — verified on a
	// real sudo — it is set even when the target is not root, which is the
	// case the guard exists for.
	t.Setenv("HOSTVEIL_ELEVATED", "")
	t.Setenv("SUDO_USER", "operator")
	if !alreadyElevated() {
		t.Error("SUDO_USER means sudo has already run; elevating again loops")
	}
}

func TestAlreadyElevatedStillHonoursTheDocumentedVariable(t *testing.T) {
	t.Setenv("SUDO_USER", "")
	t.Setenv("HOSTVEIL_ELEVATED", "1")
	if !alreadyElevated() {
		t.Error("HOSTVEIL_ELEVATED is documented and a wrapper may set it")
	}
}

// And an ordinary unprivileged shell must still elevate, or the fix would have
// turned auto-elevation off for everybody.
func TestAnOrdinaryShellIsNotAlreadyElevated(t *testing.T) {
	t.Setenv("HOSTVEIL_ELEVATED", "")
	t.Setenv("SUDO_USER", "")
	if alreadyElevated() {
		t.Error("a plain shell has neither variable set")
	}
}
