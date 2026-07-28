package platform

import (
	"path/filepath"
	"strings"
)

// nonLoginShellNames are the programs a distribution puts in a passwd shell
// field to mean "this account does not log in". They are matched by base
// name, never by full path, because the path is not portable and the name
// is: nologin lives at /usr/sbin/nologin on Debian and Ubuntu, /sbin/nologin
// on RHEL and Fedora, /usr/bin/nologin on Arch, and under
// /run/current-system/sw/bin on NixOS.
//
// "true" is here alongside "false" because /bin/true as a login shell exits
// successfully and immediately, which ends the session just as firmly as
// failing does.
var nonLoginShellNames = map[string]bool{
	"nologin": true,
	"false":   true,
	"true":    true,
}

// IsNonLoginShell reports whether a passwd shell field means the account
// cannot start an interactive session.
//
// An empty field counts. Historically it means /bin/sh, but on a modern
// distribution it appears on accounts created without a shell at all, and
// treating it as a login would report a password risk on an account that
// has no way in.
//
// This is one function because it was two, and they disagreed. The account
// domain matched the whole path against a fixed list of six spellings, so
// an Arch or NixOS host — where nologin sits at neither of the two paths it
// knew — had its service accounts read as ordinary logins, and any of them
// with an empty password field produced a Critical
// "accounts.emptypassword" for an account nobody can log in to. The Docker
// daemon domain, asking the same question about docker-group members, had
// already got this right with a suffix test. A predicate that decides
// whether to report a Critical is not one to keep two copies of.
func IsNonLoginShell(shell string) bool {
	s := strings.TrimSpace(shell)
	if s == "" {
		return true
	}
	return nonLoginShellNames[filepath.Base(s)]
}
