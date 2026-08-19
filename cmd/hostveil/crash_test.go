package main

import (
	"os"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/diagnostics"
	"github.com/seolcu/hostveil/internal/history"
)

// reportCrash is what run()'s top-level recover calls, and it is the recover
// of last resort — everything else check.runOne and internal/core's own
// crash containment do not already catch. It must never itself be able to
// panic (see its doc comment), and it must leave something for
// `hostveil bugreport` to find.
func TestReportCrashRecordsAndReportsWithoutPanicking(t *testing.T) {
	// history.DefaultDir prefers /var/lib/hostveil for root, which HOME
	// cannot redirect.
	if os.Geteuid() == 0 {
		t.Skip("running as root; HOME does not redirect history.DefaultDir")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)

	code := reportCrash([]string{"scan", "--json"}, "boom", []byte("goroutine 1 [running]:\nmain.run()"))
	if code != 1 {
		t.Errorf("got exit code %d, want 1", code)
	}

	got, err := diagnostics.Crashes(history.DefaultDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d crash records, want 1", len(got))
	}
	if got[0].Command != "scan" || got[0].Where != "cli" || !strings.Contains(got[0].Panic, "boom") {
		t.Errorf("crash record does not describe what crashed: %+v", got[0])
	}
}

// A panic reached with no arguments at all — plausible for a bug in
// resolveCommand itself — must not make reportCrash index out of range on
// args[0].
func TestReportCrashHandlesNoArguments(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; HOME does not redirect history.DefaultDir")
	}
	t.Setenv("HOME", t.TempDir())
	if code := reportCrash(nil, "boom", nil); code != 1 {
		t.Errorf("got exit code %d, want 1", code)
	}
}
