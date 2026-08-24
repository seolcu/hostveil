package diagnostics

import (
	"regexp"
	"strings"
)

var (
	ipv4Pattern = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)
	// A conservative match: any colon-separated run of hex groups that could
	// be an IPv6 address. redactIPv6 below is what keeps it from also
	// catching an ordinary H:MM:SS-shaped timestamp or duration — this
	// codebase prints plenty of those, and they contain only digits.
	ipv6Pattern  = regexp.MustCompile(`\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b`)
	homePattern  = regexp.MustCompile(`/home/[^/\s"']+`)
	usersPattern = regexp.MustCompile(`/Users/[^/\s"']+`)
)

// Redact replaces the things a bug report should not carry verbatim: IPv4
// and IPv6 addresses (loopback and unspecified addresses are left alone —
// they say nothing about the host they came from), and the account name
// embedded in a home directory path.
//
// It is a heuristic pass over free-form text, not a guarantee — that is what
// --unredacted's own warning in cmd/hostveil/diagnostics.go says, and what
// keeps this from being sold as more than it is.
func Redact(s string) string {
	s = ipv4Pattern.ReplaceAllStringFunc(s, redactIPv4)
	s = ipv6Pattern.ReplaceAllStringFunc(s, redactIPv6)
	s = homePattern.ReplaceAllString(s, "/home/<user>")
	s = usersPattern.ReplaceAllString(s, "/Users/<user>")
	return s
}

func redactIPv4(ip string) string {
	if ip == "127.0.0.1" {
		return ip
	}
	return "<ip>"
}

func redactIPv6(s string) string {
	if s == "::1" || s == "::" {
		return s
	}
	// Require a hex letter or a "::" compression before treating this as an
	// address at all. Without it, "15:04:05" — a timestamp format this
	// codebase uses throughout its own CLI and history output — matches the
	// pattern above just as well as a real address does, and both this
	// function and every fixture testing it would rather that pass through
	// unredacted than eat a date on every report.
	if !strings.ContainsAny(s, "abcdefABCDEF") && !strings.Contains(s, "::") {
		return s
	}
	return "<ip>"
}
