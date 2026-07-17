package fix

import (
	"strings"
)

// setSSHDDirective returns sshd_config bytes with key set to value. If an
// active (uncommented) directive for key exists, the first one is
// replaced in place; otherwise the directive is appended. It is pure —
// used for both preview diffs and apply.
func setSSHDDirective(in []byte, key, value string) []byte {
	lines := strings.Split(string(in), "\n")
	replaced := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(strings.ReplaceAll(trimmed, "=", " "))
		if len(fields) == 0 || !strings.EqualFold(fields[0], key) {
			continue
		}
		if strings.EqualFold(fields[0], "match") {
			break // do not edit inside/after Match blocks
		}
		lines[i] = key + " " + value
		replaced = true
		break
	}
	if !replaced {
		out := strings.TrimRight(string(in), "\n")
		if out != "" {
			out += "\n"
		}
		out += key + " " + value + "\n"
		return []byte(out)
	}
	return []byte(strings.Join(lines, "\n"))
}
