package diff

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// This diff is the last thing an operator reads before authorizing hostveil to
// write to files like /etc/ssh/sshd_config, so its output is a security
// surface, not cosmetics: a preview that omits a line the apply would write, or
// shows one it would not, hands the operator a false basis for consent. These
// tests pin the exact rendered bytes rather than substring-matching, because
// "the diff mentions PermitRootLogin somewhere" is not the property that
// matters — "the diff is precisely the change" is.
//
// Note on the format: Unified emits ---/+++ file headers, then one @@ header
// per hunk with three lines of surrounding context, eliding equal runs
// between hunks. An unterminated final line is marked. Both were once
// missing, and both were correctness problems rather than cosmetic ones: the
// unmarked newline made a real change invisible to the operator approving
// it, and echoing every line buried a one-line edit in the file it lived in.

func TestUnified(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want string
	}{
		{
			// The empty string is the contract fixflow.go leans on: previewMode
			// exists precisely because a no-op edit renders as "" and callers
			// treat that as "nothing would change".
			name: "identical inputs yield no diff",
			a:    "PermitRootLogin yes\n",
			b:    "PermitRootLogin yes\n",
			want: "",
		},
		{
			name: "identical empty inputs yield no diff",
			a:    "",
			b:    "",
			want: "",
		},
		{
			name: "pure insertion keeps surrounding lines as context",
			a:    "one\ntwo\n",
			b:    "one\ninserted\ntwo\n",
			want: "--- f\n+++ f\n@@ -1,2 +1,3 @@\n one\n+inserted\n two\n",
		},
		{
			name: "pure deletion",
			a:    "one\ngone\ntwo\n",
			b:    "one\ntwo\n",
			want: "--- f\n+++ f\n@@ -1,3 +1,2 @@\n one\n-gone\n two\n",
		},
		{
			// A replaced line is a delete followed by an add, in that order:
			// lcsDiff breaks the LCS tie toward deletion (dp[i+1][j] >=
			// dp[i][j+1]). Order matters for readability — the operator reads
			// "was X, now Y", not the reverse — so it is pinned.
			name: "replacement renders as delete then add",
			a:    "PermitRootLogin yes\n",
			b:    "PermitRootLogin no\n",
			want: "--- f\n+++ f\n@@ -1 +1 @@\n-PermitRootLogin yes\n+PermitRootLogin no\n",
		},
		{
			// The realistic sshd_config case: one directive changes inside an
			// otherwise untouched file.
			name: "single directive changed in a larger file",
			a:    "Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\n",
			b:    "Port 22\nPermitRootLogin no\nPasswordAuthentication yes\n",
			want: "--- f\n+++ f\n@@ -1,3 +1,3 @@\n Port 22\n-PermitRootLogin yes\n+PermitRootLogin no\n PasswordAuthentication yes\n",
		},
		{
			name: "empty original renders as all additions",
			a:    "",
			b:    "alpha\nbeta\n",
			want: "--- f\n+++ f\n@@ -0,0 +1,2 @@\n+alpha\n+beta\n",
		},
		{
			name: "empty replacement renders as all deletions",
			a:    "alpha\nbeta\n",
			b:    "",
			want: "--- f\n+++ f\n@@ -1,2 +0,0 @@\n-alpha\n-beta\n",
		},
		{
			// splitLines strips exactly one trailing newline, so both sides
			// produce the same line slice and the LCS sees no change. The
			// final line is therefore forced apart into a delete and an add
			// so the marker can say which side lost its terminator — what
			// git does for the same case. See the dedicated test below.
			name: "trailing newline only difference renders both sides",
			a:    "alpha\n",
			b:    "alpha",
			want: "--- f\n+++ f\n@@ -1 +1 @@\n-alpha\n+alpha\n\\ No newline at end of file\n",
		},
		{
			// Only the *last* newline is stripped, so a blank final line is a
			// real, visible line in the diff.
			name: "blank line is a content line",
			a:    "alpha\n\n",
			b:    "alpha\n",
			want: "--- f\n+++ f\n@@ -1,2 +1 @@\n alpha\n-\n",
		},
		{
			// Two changes separated by four unchanged lines. Splitting here
			// would emit two hunks whose context overlapped, repeating the
			// middle lines, so they merge into one instead.
			name: "changes closer than twice the context share one hunk",
			a:    "a\nk1\nk2\nk3\nk4\nb\n",
			b:    "A\nk1\nk2\nk3\nk4\nB\n",
			want: "--- f\n+++ f\n@@ -1,6 +1,6 @@\n-a\n+A\n k1\n k2\n k3\n k4\n-b\n+B\n",
		},
		{
			name: "wholly disjoint texts",
			a:    "x\ny\n",
			b:    "p\nq\n",
			want: "--- f\n+++ f\n@@ -1,2 +1,2 @@\n-x\n-y\n+p\n+q\n",
		},
		{
			// Repeated lines are where a naive diff drifts: the LCS must match
			// through the common run rather than deleting and re-adding it.
			// Equality is tested before the LCS tie-break, so the walk consumes
			// matches greedily and the deletion lands at the end of the run.
			name: "repeated lines match through the common run",
			a:    "dup\ndup\ndup\n",
			b:    "dup\ndup\n",
			want: "--- f\n+++ f\n@@ -1,3 +1,2 @@\n dup\n dup\n-dup\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Unified("f", tt.a, tt.b)
			if got != tt.want {
				t.Errorf("Unified(%q, %q, %q) mismatch\n got: %q\nwant: %q", "f", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// TestUnifiedLabelsBothSidesWithPath pins the header, because the path is the
// operator's only confirmation of *which* file is about to be written. A fix
// preview showing the right change against the wrong file is worse than no
// preview.
func TestUnifiedHeaderNamesTheFile(t *testing.T) {
	got := Unified("/etc/ssh/sshd_config", "a\n", "b\n")
	const wantPrefix = "--- /etc/ssh/sshd_config\n+++ /etc/ssh/sshd_config\n"
	if !strings.HasPrefix(got, wantPrefix) {
		t.Errorf("header missing or malformed:\n%s", got)
	}
}

// TestUnifiedNewlineOnlyChangeIsVisible pins the fix for a preview that
// used to lie. splitLines drops the trailing newline, so a transform whose
// only effect was adding or removing the file's final newline produced a
// diff with a header and nothing but context: non-empty, so fixflow treated
// it as "there is a change to review", yet showing the operator zero +/-
// lines to review — while applyEdit wrote the differing bytes. The preview
// and the write disagreed. Both sides of the change must now be visible and
// the missing terminator stated.
func TestUnifiedNewlineOnlyChangeIsVisible(t *testing.T) {
	for _, tc := range []struct{ name, a, b string }{
		{"newline added", "PermitRootLogin no", "PermitRootLogin no\n"},
		{"newline removed", "PermitRootLogin no\n", "PermitRootLogin no"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Unified("/etc/ssh/sshd_config", tc.a, tc.b)
			if got == "" {
				t.Fatal("expected a non-empty diff for differing inputs")
			}
			var changed int
			for _, line := range strings.Split(got, "\n") {
				if strings.HasPrefix(line, "+++") || strings.HasPrefix(line, "---") {
					continue
				}
				if strings.HasPrefix(line, "+") || strings.HasPrefix(line, "-") {
					changed++
				}
			}
			if changed != 2 {
				t.Errorf("expected the line to render on both sides, got %d changed lines:\n%s", changed, got)
			}
			if !strings.Contains(got, noNewline) {
				t.Errorf("the missing final newline is not stated:\n%s", got)
			}
		})
	}
}

// TestUnifiedElidesDistantContext is the other half of the preview being
// readable: a one-line edit to a long file must show the edit and its
// neighbourhood, not the whole file. Before hunking, authorizing a single
// change to a several-hundred-line compose file meant reading the entire
// file back with one line marked.
func TestUnifiedElidesDistantContext(t *testing.T) {
	var a, b strings.Builder
	for i := range 200 {
		a.WriteString(fmt.Sprintf("line%d\n", i))
		if i == 100 {
			b.WriteString("changed\n")
			continue
		}
		b.WriteString(fmt.Sprintf("line%d\n", i))
	}
	got := Unified("big.conf", a.String(), b.String())

	body := strings.Split(strings.TrimRight(got, "\n"), "\n")[2:]
	// One @@ header, 2*contextLines of context, one '-' and one '+'.
	if want := 1 + 2*contextLines + 2; len(body) != want {
		t.Errorf("hunk should be %d lines, got %d:\n%s", want, len(body), got)
	}
	if !strings.Contains(got, "@@ -98,7 +98,7 @@") {
		t.Errorf("hunk header does not locate the change at line 101:\n%s", got)
	}
	if strings.Contains(got, "line5\n") {
		t.Errorf("distant context was not elided:\n%s", got)
	}
}

// TestUnifiedSeparatesDistantChanges: two edits far apart get their own
// hunks, so neither is buried in the other's context.
func TestUnifiedSeparatesDistantChanges(t *testing.T) {
	var a, b strings.Builder
	for i := range 100 {
		a.WriteString(fmt.Sprintf("line%d\n", i))
		switch i {
		case 10, 80:
			b.WriteString(fmt.Sprintf("changed%d\n", i))
		default:
			b.WriteString(fmt.Sprintf("line%d\n", i))
		}
	}
	got := Unified("big.conf", a.String(), b.String())
	if n := strings.Count(got, "@@ -"); n != 2 {
		t.Errorf("expected 2 hunks for 2 distant changes, got %d:\n%s", n, got)
	}
}

// TestUnifiedHandlesLargeInputs guards against the quadratic LCS table blowing
// up on a realistically sized config. sshd_config is ~120 lines; docker-compose
// files can be several hundred. This is a smoke test for termination and shape,
// not a benchmark.
func TestUnifiedLargeInput(t *testing.T) {
	var a, b strings.Builder
	for i := range 2000 {
		a.WriteString("line\n")
		if i == 1000 {
			b.WriteString("changed\n")
			continue
		}
		b.WriteString("line\n")
	}
	got := Unified("big.conf", a.String(), b.String())
	if strings.Count(got, "\n+changed") != 1 {
		t.Errorf("expected exactly one added line, got:\n%s", got[:min(len(got), 400)])
	}
}

// FuzzUnified asserts the property that makes a preview trustworthy: the diff
// must be a faithful, lossless rendering of both texts. Because Unified emits
// every line (no hunks, no elided context), the reconstruction is exact at line
// granularity — the ' ' and '-' lines rebuild the original, the ' ' and '+'
// lines rebuild the modification.
//
// The one documented lossiness is the trailing newline: splitLines strips it,
// so reconstruction is compared against splitLines' output rather than against
// the raw strings. That weaker form is still the meaningful invariant — it
// catches any line that is dropped, duplicated, reordered, or attributed to the
// wrong side, which is the whole class of "the preview lied" failures.
func FuzzUnified(f *testing.F) {
	f.Add("PermitRootLogin yes\n", "PermitRootLogin no\n")
	f.Add("", "")
	f.Add("a\nb\nc\n", "a\nc\n")
	f.Add("a\nb\n", "a\nb")
	f.Add("dup\ndup\ndup\n", "dup\n")
	f.Add("\n\n\n", "\n")
	f.Add("x", "")

	f.Fuzz(func(t *testing.T, a, b string) {
		got := Unified("p", a, b)

		if got == "" {
			if a != b {
				t.Fatalf("empty diff for differing inputs: %q vs %q", a, b)
			}
			return
		}
		if a == b {
			t.Fatalf("non-empty diff for identical inputs %q:\n%s", a, got)
		}

		// The rendered body always ends in "\n", so Split leaves one trailing
		// empty element. An empty *content* line renders as " ", never "", so
		// only that final element is spurious.
		lines := strings.Split(got, "\n")
		if lines[len(lines)-1] != "" {
			t.Fatalf("diff does not end in a newline: %q", got)
		}
		lines = lines[:len(lines)-1]

		if len(lines) < 2 || lines[0] != "--- p" || lines[1] != "+++ p" {
			t.Fatalf("malformed header: %q", got)
		}

		// Now that equal runs are elided, the body no longer reconstructs the
		// whole file — so the property checked is the one that actually makes
		// a hunk trustworthy: every hunk's own line numbers must locate it
		// exactly, and its ' '/'-' lines must be the original's lines at that
		// offset, its ' '/'+' lines the modification's. A hunk that renders
		// real lines at the wrong place is as misleading as a missing one.
		aLines, _ := splitLines(a)
		bLines, _ := splitLines(b)

		var hunkCount int
		var claims []*hunkClaim
		var cur *hunkClaim
		flush := func() {
			if cur == nil {
				return
			}
			cur.verify(t, aLines, bLines, got)
			claims = append(claims, cur)
			cur = nil
		}
		for _, line := range lines[2:] {
			if strings.HasPrefix(line, "@@ ") {
				flush()
				hunkCount++
				cur = parseHunkHeader(t, line, got)
				continue
			}
			if cur == nil {
				t.Fatalf("body line %q before any @@ header in:\n%s", line, got)
			}
			if line == noNewline {
				cur.sawMarker = true
				continue
			}
			if line == "" {
				t.Fatalf("body line with no marker prefix: %q", got)
			}
			switch line[0] {
			case ' ':
				cur.a = append(cur.a, line[1:])
				cur.b = append(cur.b, line[1:])
			case '-':
				cur.a = append(cur.a, line[1:])
			case '+':
				cur.b = append(cur.b, line[1:])
			default:
				t.Fatalf("body line with unknown marker %q in:\n%s", line[0], got)
			}
		}
		flush()

		if hunkCount == 0 {
			t.Fatalf("differing inputs produced no hunk:\n%s", got)
		}
		// A missing terminator must be stated whenever the line it belongs to
		// is actually on screen, or the operator approves bytes the diff never
		// showed. It must NOT be stated otherwise: when the change is far from
		// the end of the file, the unterminated last line is elided as distant
		// context and there is nothing for the marker to attach to.
		_, aEOL := splitLines(a)
		_, bEOL := splitLines(b)
		wantMarker := (!aEOL && rendersLastLine(claims, "a", len(aLines))) ||
			(!bEOL && rendersLastLine(claims, "b", len(bLines)))
		if hasMarker := strings.Contains(got, noNewline); hasMarker != wantMarker {
			t.Fatalf("no-newline marker present=%v, want %v:\n%s", hasMarker, wantMarker, got)
		}
	})
}

// hunkClaim is one @@ header plus the lines rendered under it: what the
// diff claims about a region of each file.
type hunkClaim struct {
	aStart, aCount int
	bStart, bCount int
	a, b           []string
	sawMarker      bool
}

func parseHunkHeader(t *testing.T, line, whole string) *hunkClaim {
	t.Helper()
	m := regexp.MustCompile(`^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@$`).FindStringSubmatch(line)
	if m == nil {
		t.Fatalf("malformed hunk header %q in:\n%s", line, whole)
	}
	num := func(s string, def int) int {
		if s == "" {
			return def
		}
		n, err := strconv.Atoi(s)
		if err != nil {
			t.Fatalf("bad number %q in header %q", s, line)
		}
		return n
	}
	return &hunkClaim{
		aStart: num(m[1], 0), aCount: num(m[2], 1),
		bStart: num(m[3], 0), bCount: num(m[4], 1),
	}
}

// rendersLastLine reports whether any hunk's range for the given side
// reaches the file's final line.
func rendersLastLine(claims []*hunkClaim, side string, total int) bool {
	for _, h := range claims {
		start, count := h.aStart, h.aCount
		if side == "b" {
			start, count = h.bStart, h.bCount
		}
		if count > 0 && start-1+count == total {
			return true
		}
	}
	return false
}

func (h *hunkClaim) verify(t *testing.T, aLines, bLines []string, whole string) {
	t.Helper()
	check := func(side string, start, count int, got, file []string) {
		if len(got) != count {
			t.Fatalf("%s: header claims %d lines but %d rendered in:\n%s", side, count, len(got), whole)
		}
		if count == 0 {
			return
		}
		if start < 1 || start-1+count > len(file) {
			t.Fatalf("%s: hunk range %d,%d is outside the %d-line file in:\n%s",
				side, start, count, len(file), whole)
		}
		if !equalLines(got, file[start-1:start-1+count]) {
			t.Fatalf("%s: hunk at %d,%d renders %q but the file has %q in:\n%s",
				side, start, count, got, file[start-1:start-1+count], whole)
		}
	}
	check("original", h.aStart, h.aCount, h.a, aLines)
	check("modified", h.bStart, h.bCount, h.b, bLines)
}

func equalLines(x, y []string) bool {
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}
