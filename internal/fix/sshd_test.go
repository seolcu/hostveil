package fix

import "testing"

// A Match block is a conditional override: everything under it applies only
// to the sessions it selects. The checker knows this and stops parsing at the
// first Match, so every finding it reports is about the *global* configuration
// above one.
//
// setSSHDDirective has a guard meant to keep the fix on the same footing —
// "do not edit inside/after Match blocks" — and it cannot fire. The keyword
// test above it already requires the line to be the directive being set, so
// the Match test is only reachable when the directive *is* "match", which no
// fix sets. Both halves of the editor walk into the block as a result.

// The directive exists, but only inside a Match block. Editing it changes what
// SSH does for the sessions that block selects — something the operator wrote
// deliberately and the finding never referred to — while the global setting
// the finding was actually about stays exactly as it was.
func TestDirectiveInsideAMatchBlockIsLeftAlone(t *testing.T) {
	in := []byte("PermitRootLogin no\n" +
		"\n" +
		"Match User deploy\n" +
		"    PasswordAuthentication yes\n")

	out := string(setSSHDDirective(in, "PasswordAuthentication", "no"))

	if contains(out, "Match User deploy\n    PasswordAuthentication no") {
		t.Error("the fix rewrote a directive inside a Match block: it changed " +
			"password auth for the deploy user and left the global default alone")
	}
	if !contains(out, "Match User deploy\n    PasswordAuthentication yes") {
		t.Errorf("the Match block was modified:\n%s", out)
	}
}

// The directive is absent, so the fix appends it — and appending to the end of
// a file that ends in a Match block puts it *inside* that block. The operator
// asked to disable password authentication everywhere and got it disabled for
// one user, with the global default untouched and the finding still true.
func TestAppendGoesAboveATrailingMatchBlock(t *testing.T) {
	in := []byte("PermitRootLogin no\n" +
		"\n" +
		"Match User deploy\n" +
		"    X11Forwarding yes\n")

	out := string(setSSHDDirective(in, "PasswordAuthentication", "no"))

	global := indexOf(out, "PasswordAuthentication no")
	match := indexOf(out, "Match User deploy")
	if global < 0 {
		t.Fatalf("the directive was not added at all:\n%s", out)
	}
	if global > match {
		t.Errorf("the directive was appended inside the trailing Match block, so it "+
			"applies to that block only rather than globally:\n%s", out)
	}
}

// The ordinary case has to keep working: with no Match block, an absent
// directive is appended at the end.
func TestAppendWithoutAMatchBlockGoesAtTheEnd(t *testing.T) {
	out := string(setSSHDDirective([]byte("PermitRootLogin no\n"), "PasswordAuthentication", "no"))
	if want := "PermitRootLogin no\nPasswordAuthentication no\n"; out != want {
		t.Errorf("got %q, want %q", out, want)
	}
}

// And a directive above a Match block is still the one that gets rewritten —
// that is the global setting the finding is about.
func TestDirectiveAboveAMatchBlockIsRewritten(t *testing.T) {
	in := []byte("PasswordAuthentication yes\n" +
		"\n" +
		"Match User deploy\n" +
		"    X11Forwarding yes\n")

	out := string(setSSHDDirective(in, "PasswordAuthentication", "no"))

	if !contains(out, "PasswordAuthentication no") {
		t.Errorf("the global directive was not rewritten:\n%s", out)
	}
	if !contains(out, "Match User deploy") || !contains(out, "X11Forwarding yes") {
		t.Errorf("the Match block was damaged:\n%s", out)
	}
}

func contains(s, sub string) bool { return indexOf(s, sub) >= 0 }

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
