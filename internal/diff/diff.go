// Package diff produces a compact unified diff between two texts. Fixes
// make small, localized edits, so a straightforward LCS-based diff is both
// correct and readable in previews.
//
// The output is the last thing an operator reads before authorizing a write
// to a file like /etc/ssh/sshd_config, which makes two properties matter
// more than they would in a general-purpose diff. It must show every byte
// the apply would change — a change the preview cannot render is consent
// obtained on a false basis. And it must show little else: a one-line edit
// to a several-hundred-line compose file that echoes the whole file buries
// the very line being authorized.
package diff

import (
	"fmt"
	"strings"
)

// contextLines is how many unchanged lines surround each change. Three is
// the conventional unified-diff default and is enough to locate an edit in
// a config file without reproducing it.
const contextLines = 3

// noNewline is the standard marker for a final line with no line ending.
// Without it a missing trailing newline is invisible: both sides split to
// the same lines, the diff renders as pure context, and the operator is
// asked to approve a change they cannot see while applyEdit writes
// different bytes.
const noNewline = "\\ No newline at end of file"

// Unified returns a unified diff of a→b labeled with path. It returns the
// empty string when the inputs are identical.
func Unified(path, a, b string) string {
	if a == b {
		return ""
	}
	al, aHasEOL := splitLines(a)
	bl, bHasEOL := splitLines(b)
	ops := lcsDiff(al, bl)

	// When the sides differ only in whether the final line is terminated,
	// every line matches and the LCS emits nothing but context. Split that
	// final equal line into a delete and an add so each side can carry its
	// own marker, which is what git does for the same case.
	if aHasEOL != bHasEOL && len(ops) > 0 {
		if last := ops[len(ops)-1]; last.kind == opEqual {
			ops = append(ops[:len(ops)-1],
				op{kind: opDel, line: last.line, aLine: last.aLine},
				op{kind: opAdd, line: last.line, bLine: last.bLine})
		}
	}

	var out strings.Builder
	fmt.Fprintf(&out, "--- %s\n+++ %s\n", path, path)
	for _, h := range hunks(ops) {
		writeHunk(&out, ops[h.start:h.end], len(al), len(bl), aHasEOL, bHasEOL)
	}
	return out.String()
}

type opKind int

const (
	opEqual opKind = iota
	opDel
	opAdd
)

type op struct {
	kind  opKind
	line  string
	aLine int // 1-based line number in a; 0 for an addition
	bLine int // 1-based line number in b; 0 for a deletion
}

func (o op) changed() bool { return o.kind != opEqual }

// splitLines splits s into lines and reports whether it ended with a
// newline. The terminator is not part of the last line, but whether it was
// there is a real difference between two texts, so it is returned rather
// than discarded. The empty string has no final line to be unterminated,
// so it reports true.
func splitLines(s string) (lines []string, hasEOL bool) {
	if s == "" {
		return nil, true
	}
	if hasEOL = strings.HasSuffix(s, "\n"); hasEOL {
		s = s[:len(s)-1]
	}
	return strings.Split(s, "\n"), hasEOL
}

// hunkRange is a half-open range of ops forming one hunk.
type hunkRange struct{ start, end int }

// hunks groups changed ops into hunks, each padded by contextLines of
// surrounding equal lines. Ranges that would touch or overlap are merged,
// so two edits three lines apart render as one hunk rather than two that
// repeat the same context.
func hunks(ops []op) []hunkRange {
	var out []hunkRange
	for i := 0; i < len(ops); {
		if !ops[i].changed() {
			i++
			continue
		}
		// Walk forward absorbing later changes while the equal run between
		// them is short enough that two hunks would repeat context anyway.
		last := i
		for j := i + 1; j < len(ops); j++ {
			if !ops[j].changed() {
				continue
			}
			if j-last-1 > 2*contextLines {
				break
			}
			last = j
		}
		out = append(out, hunkRange{
			start: max(0, i-contextLines),
			end:   min(len(ops), last+1+contextLines),
		})
		i = last + 1
	}
	return out
}

// writeHunk emits one hunk: the @@ header naming both line ranges, then the
// lines. A no-newline marker follows the final line of whichever side lacks
// a terminator.
func writeHunk(out *strings.Builder, ops []op, aTotal, bTotal int, aHasEOL, bHasEOL bool) {
	aStart, aCount, bStart, bCount := hunkBounds(ops)
	fmt.Fprintf(out, "@@ -%s +%s @@\n", rangeSpec(aStart, aCount), rangeSpec(bStart, bCount))

	for _, o := range ops {
		switch o.kind {
		case opEqual:
			fmt.Fprintf(out, " %s\n", o.line)
		case opDel:
			fmt.Fprintf(out, "-%s\n", o.line)
		case opAdd:
			fmt.Fprintf(out, "+%s\n", o.line)
		}
		// The marker belongs to the side whose last line this is. An equal
		// line is the last of both, and reaches here only when the two
		// sides agree about the terminator.
		lastOfA := o.kind != opAdd && o.aLine == aTotal
		lastOfB := o.kind != opDel && o.bLine == bTotal
		if (lastOfA && !aHasEOL) || (lastOfB && !bHasEOL) {
			fmt.Fprintf(out, "%s\n", noNewline)
		}
	}
}

// hunkBounds returns the 1-based start and the line count for each side.
// A side contributing no lines gets start 0, which is the unified-diff
// convention for an empty range.
func hunkBounds(ops []op) (aStart, aCount, bStart, bCount int) {
	for _, o := range ops {
		if o.kind != opAdd {
			if aStart == 0 {
				aStart = o.aLine
			}
			aCount++
		}
		if o.kind != opDel {
			if bStart == 0 {
				bStart = o.bLine
			}
			bCount++
		}
	}
	return aStart, aCount, bStart, bCount
}

func rangeSpec(start, count int) string {
	if count == 1 {
		return fmt.Sprintf("%d", start)
	}
	return fmt.Sprintf("%d,%d", start, count)
}

// lcsDiff computes edit operations via a longest-common-subsequence DP.
func lcsDiff(a, b []string) []op {
	n, m := len(a), len(b)
	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else if dp[i+1][j] >= dp[i][j+1] {
				dp[i][j] = dp[i+1][j]
			} else {
				dp[i][j] = dp[i][j+1]
			}
		}
	}
	var ops []op
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			ops = append(ops, op{kind: opEqual, line: a[i], aLine: i + 1, bLine: j + 1})
			i++
			j++
		case dp[i+1][j] >= dp[i][j+1]:
			ops = append(ops, op{kind: opDel, line: a[i], aLine: i + 1})
			i++
		default:
			ops = append(ops, op{kind: opAdd, line: b[j], bLine: j + 1})
			j++
		}
	}
	for ; i < n; i++ {
		ops = append(ops, op{kind: opDel, line: a[i], aLine: i + 1})
	}
	for ; j < m; j++ {
		ops = append(ops, op{kind: opAdd, line: b[j], bLine: j + 1})
	}
	return ops
}
