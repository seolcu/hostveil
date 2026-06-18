package version

import "fmt"

// String returns the canonical "hostveil vX.Y.Z (commit <sha>, built
// <RFC3339>)" form used by `hostveil version` and locked by
// tests/contract/version_test.go.
func String() string {
	return fmt.Sprintf("%s %s (commit %s, built %s)", Name, Version, Commit, Built)
}
