// Package diff produces a compact unified diff between two texts. Fixes
// make small, localized edits, so a straightforward LCS-based diff is both
// correct and readable in previews.
package diff

import (
	"fmt"
	"strings"
)

// Unified returns a unified diff of a→b labeled with path. It returns the
// empty string when the inputs are identical.
func Unified(path, a, b string) string {
	if a == b {
		return ""
	}
	al := splitLines(a)
	bl := splitLines(b)
	ops := lcsDiff(al, bl)

	var out strings.Builder
	fmt.Fprintf(&out, "--- %s\n+++ %s\n", path, path)
	for _, op := range ops {
		switch op.kind {
		case opEqual:
			fmt.Fprintf(&out, " %s\n", op.line)
		case opDel:
			fmt.Fprintf(&out, "-%s\n", op.line)
		case opAdd:
			fmt.Fprintf(&out, "+%s\n", op.line)
		}
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
	kind opKind
	line string
}

func splitLines(s string) []string {
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
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
			ops = append(ops, op{opEqual, a[i]})
			i++
			j++
		case dp[i+1][j] >= dp[i][j+1]:
			ops = append(ops, op{opDel, a[i]})
			i++
		default:
			ops = append(ops, op{opAdd, b[j]})
			j++
		}
	}
	for ; i < n; i++ {
		ops = append(ops, op{opDel, a[i]})
	}
	for ; j < m; j++ {
		ops = append(ops, op{opAdd, b[j]})
	}
	return ops
}
