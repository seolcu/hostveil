package fix

import (
	"slices"
	"strings"
)

// setSSHDDirective returns sshd_config bytes with key set to value, confined
// to the file's global section. If an active (uncommented) directive for key
// exists there, the first one is replaced in place; otherwise the directive is
// inserted at the end of that section. It is pure — used for both preview
// diffs and apply.
//
// The global section is everything above the first Match. A Match block is a
// conditional override that applies only to the sessions it selects, and
// internal/check/ssh stops parsing at the first one for exactly that reason —
// so every finding it reports is a statement about the global configuration,
// and the fix has to answer in the same terms.
//
// This used to be attempted by a guard inside the replace loop that could
// never fire: the keyword test above it already required the line to be the
// directive being set, so the Match test was reachable only when the
// directive *was* "match", which nothing sets. Both halves of the editor
// walked into the block. A `PasswordAuthentication yes` under `Match User
// deploy` was rewritten as though it were the global default — changing what
// SSH did for that user, which the operator had chosen deliberately and the
// finding never referred to, while the global setting stayed as it was. And
// when the directive was absent, appending it to the end of a file that ends
// in a Match block put it inside that block, so "disable password
// authentication" quietly meant "disable it for one user". Both results are
// valid sshd_config, so `sshd -t` accepts them and the fix reports success.
func setSSHDDirective(in []byte, key, value string) []byte {
	lines := strings.Split(string(in), "\n")

	// Where the global section ends. len(lines) when the file has no Match,
	// which is the ordinary case.
	limit := len(lines)
	for i, line := range lines {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) > 0 && strings.EqualFold(fields[0], "match") {
			limit = i
			break
		}
	}

	for i, line := range lines[:limit] {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(strings.ReplaceAll(trimmed, "=", " "))
		if len(fields) == 0 || !strings.EqualFold(fields[0], key) {
			continue
		}
		lines[i] = key + " " + value
		return []byte(strings.Join(lines, "\n"))
	}

	// Absent from the global section. With a Match block present the
	// directive goes immediately above it, since the end of the file is
	// inside the block.
	if limit < len(lines) {
		return []byte(strings.Join(slices.Insert(lines, limit, key+" "+value), "\n"))
	}

	out := strings.TrimRight(string(in), "\n")
	if out != "" {
		out += "\n"
	}
	out += key + " " + value + "\n"
	return []byte(out)
}
