// Package fileperms implements a native checker for over-permissive modes
// on sensitive host files. A world-writable /etc/passwd or a group-readable
// SSH host key is a quiet but serious hole; this checker stats a curated set
// of security-critical files and flags any whose permission bits are looser
// than they should ever be.
package fileperms

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// Rule declares the strictest acceptable permission for one sensitive file.
// A file is flagged when its permission bits include anything outside
// MaxMode (i.e. perm &^ MaxMode != 0).
type Rule struct {
	Path    string      // exact path, or a glob when Glob is true
	Glob    bool        // expand Path with filepath.Glob (e.g. SSH host keys)
	MaxMode os.FileMode // strictest acceptable perm bits
	Sev     model.Severity
	ID      string
	Title   string
	Desc    string
}

// Checker reports sensitive files with over-permissive modes.
type Checker struct {
	// Rules is the set of files to check; overridable for tests.
	Rules []Rule
}

// New returns a fileperms checker with the default sensitive-file rules.
func New() *Checker { return &Checker{Rules: defaultRules()} }

func defaultRules() []Rule {
	return []Rule{
		{Path: "/etc/shadow", MaxMode: 0o640, Sev: model.SeverityHigh, ID: "fileperms.shadow",
			Title: "/etc/shadow is more permissive than it should be",
			Desc:  "/etc/shadow holds every account's password hash. If it is readable or writable beyond root (and the shadow group), those hashes can be stolen and cracked offline, or an attacker can set a password directly."},
		{Path: "/etc/passwd", MaxMode: 0o644, Sev: model.SeverityHigh, ID: "fileperms.passwd",
			Title: "/etc/passwd is writable by non-root users",
			Desc:  "/etc/passwd defines every account. If it is writable by anyone but root, a local user can add an account or change a UID to escalate to root."},
		{Path: "/etc/group", MaxMode: 0o644, Sev: model.SeverityHigh, ID: "fileperms.group",
			Title: "/etc/group is writable by non-root users",
			Desc:  "/etc/group defines group membership. If it is writable by non-root users, a local user can add themselves to a privileged group (e.g. sudo, docker) and escalate."},
		{Path: "/etc/ssh/sshd_config", MaxMode: 0o644, Sev: model.SeverityMedium, ID: "fileperms.sshd-config",
			Title: "sshd_config is writable by non-root users",
			Desc:  "If the SSH server config is writable by non-root users, an attacker can weaken it (re-enable root login or password auth) and take over remote access."},
		{Path: "/etc/ssh/ssh_host_*_key", Glob: true, MaxMode: 0o640, Sev: model.SeverityHigh, ID: "fileperms.hostkey",
			Title: "SSH host private key is readable beyond root",
			Desc:  "An SSH host private key readable by non-root users lets them impersonate this server, enabling man-in-the-middle attacks on anyone connecting over SSH."},
	}
}

// Source identifies the fileperms domain.
func (*Checker) Source() model.Source { return model.SourceFilePerms }

// Available is always true: it simply stats whichever of its target files
// exist and skips the rest.
func (*Checker) Available(_ context.Context, _ platform.Env) (bool, string) {
	return true, ""
}

// Check stats each rule's file(s) and flags any over-permissive mode.
func (c *Checker) Check(_ context.Context, _ platform.Env) ([]model.Finding, error) {
	var findings []model.Finding
	for _, rule := range c.Rules {
		paths := []string{rule.Path}
		if rule.Glob {
			matches, err := filepath.Glob(rule.Path)
			if err != nil || len(matches) == 0 {
				continue
			}
			paths = matches
		}
		var bad []string
		for _, p := range paths {
			fi, err := os.Stat(p)
			if err != nil || fi.IsDir() {
				continue // missing files (e.g. no SSH server) are not findings
			}
			if fi.Mode().Perm()&^rule.MaxMode != 0 {
				bad = append(bad, fmt.Sprintf("%s (%#o)", p, fi.Mode().Perm()))
			}
		}
		if len(bad) == 0 {
			continue
		}
		sort.Strings(bad)
		findings = append(findings, model.NewFinding(rule.ID, rule.Title, rule.Sev,
			model.SourceFilePerms, model.RemediationManual,
			model.WithDescription(rule.Desc),
			model.WithHowToFix(fmt.Sprintf("Tighten the mode to %#o or stricter, e.g. `chmod %#o %s`.", rule.MaxMode, rule.MaxMode, firstPath(bad))),
			model.WithEvidence("files", strings.Join(bad, ", ")),
			model.WithEvidence("expected", fmt.Sprintf("%#o", rule.MaxMode)),
		))
	}
	return findings, nil
}

// firstPath returns the path portion of the first "path (mode)" entry, for
// use in an example chmod command.
func firstPath(bad []string) string {
	if len(bad) == 0 {
		return ""
	}
	if i := strings.Index(bad[0], " ("); i >= 0 {
		return bad[0][:i]
	}
	return bad[0]
}
