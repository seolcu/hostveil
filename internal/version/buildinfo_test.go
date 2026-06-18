package version

import "testing"

func TestString(t *testing.T) {
	prevV, prevC, prevB := Version, Commit, Built
	t.Cleanup(func() { Version, Commit, Built = prevV, prevC, prevB })

	Version = "v3.0.0"
	Commit = "abc1234"
	Built = "2026-06-18T00:00:00Z"
	got := String()
	want := "hostveil v3.0.0 (commit abc1234, built 2026-06-18T00:00:00Z)"
	if got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}
