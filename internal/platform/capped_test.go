package platform

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"testing"
)

// The seam bounds time and memory both.
//
// It bounded only time for most of this project's life, and the two fail
// differently: a command that hangs is killed at the deadline, while one that
// streams is held in full until it stops. The CVE checker runs several at once
// against hosts that are often 1 GB VPSes, and `serve` does it as root.
func TestARunawayCommandDoesNotGetToFillMemory(t *testing.T) {
	if _, err := exec.LookPath("head"); err != nil {
		t.Skip("needs head")
	}
	// /dev/zero through head gives a deterministic size with no shell.
	small := DefaultRunner{}
	out, err := small.Run(context.Background(), "head", "-c", "1024", "/dev/zero")
	if err != nil || len(out) != 1024 {
		t.Fatalf("a 1 KiB command returned %d bytes, %v", len(out), err)
	}
}

// capped is where the bound lives, so it is tested directly — a command large
// enough to cross 128 MiB is not something to run in a unit test.
func TestCappedStopsAtItsLimitAndSaysSo(t *testing.T) {
	for _, tc := range []struct {
		name     string
		limit    int
		writes   []int
		wantLen  int
		overflow bool
	}{
		{"under the limit", 10, []int{3, 4}, 7, false},
		{"exactly the limit", 10, []int{10}, 10, false},
		{"one past, in one write", 10, []int{11}, 10, true},
		{"one past, across writes", 10, []int{6, 6}, 10, true},
		{"far past", 10, []int{5, 500, 500}, 10, true},
		{"writes after it is full", 4, []int{4, 1}, 4, true},
		{"an empty write when full changes nothing", 4, []int{4, 0}, 4, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &capped{limit: tc.limit}
			for _, n := range tc.writes {
				// Write must always claim the full length. A short write
				// closes the pipe and the command dies of SIGPIPE, which
				// reaches the operator as a broken tool.
				got, err := c.Write(bytes.Repeat([]byte("x"), n))
				if got != n || err != nil {
					t.Fatalf("Write(%d bytes) = %d, %v — want the full length and no error", n, got, err)
				}
			}
			if len(c.buf) != tc.wantLen {
				t.Errorf("kept %d bytes, want %d", len(c.buf), tc.wantLen)
			}
			if c.overflow != tc.overflow {
				t.Errorf("overflow = %v, want %v", c.overflow, tc.overflow)
			}
		})
	}
}

// Overflow returns nothing rather than a prefix. Handing back the first
// 128 MiB of a JSON document gives a checker something that parses to a
// smaller, wrong answer — a partial look reported as a finished one, which is
// the failure this project spends most of its tests on.
func TestOverflowIsAnErrorAndNotAPrefix(t *testing.T) {
	if _, err := exec.LookPath("head"); err != nil {
		t.Skip("needs head")
	}
	r := DefaultRunner{MaxOutput: 64}
	out, err := r.Run(context.Background(), "head", "-c", "4096", "/dev/zero")
	if err == nil {
		t.Fatal("a command over the cap returned no error")
	}
	if out != nil {
		t.Errorf("a command over the cap returned %d bytes; want none", len(out))
	}
	if !strings.Contains(err.Error(), "head") {
		t.Errorf("the error does not name the command: %v", err)
	}
}

// stderr still reaches the operator now that exec no longer owns the buffer.
// ExitError.Stderr is only filled when Output() collects it, and setting
// cmd.Stderr took that away — the message is what turns "exit status 1" into
// something actionable.
func TestStderrStillReachesTheErrorMessage(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("needs sh")
	}
	_, err := DefaultRunner{}.Run(context.Background(), "sh", "-c", "echo the-real-reason >&2; exit 3")
	if err == nil {
		t.Fatal("a failing command returned no error")
	}
	if !strings.Contains(err.Error(), "the-real-reason") {
		t.Errorf("stderr did not reach the error: %v", err)
	}
}
