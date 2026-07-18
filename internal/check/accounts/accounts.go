// Package accounts implements a native host account-hygiene checker. It
// parses /etc/passwd and /etc/shadow to catch two classic, high-impact
// mistakes a self-hoster can make without realizing: a second account with
// root's UID, and a login account with no password at all.
package accounts

import (
	"context"
	"os"
	"sort"
	"strings"

	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// Checker reports account-hygiene problems from the local user databases.
type Checker struct {
	// PasswdPath and ShadowPath are overridable for tests.
	PasswdPath string
	ShadowPath string
}

// New returns an accounts checker reading the standard system databases.
func New() *Checker {
	return &Checker{PasswdPath: "/etc/passwd", ShadowPath: "/etc/shadow"}
}

// Source identifies the accounts domain.
func (*Checker) Source() model.Source { return model.SourceAccounts }

// Available requires a readable /etc/passwd. /etc/shadow may still be
// unreadable without root; Check handles that by running the passwd-only
// checks and skipping the password check.
func (c *Checker) Available(_ context.Context, _ platform.Env) (bool, string) {
	if _, err := os.ReadFile(c.PasswdPath); err != nil { //nolint:gosec // fixed system path
		return false, "cannot read " + c.PasswdPath
	}
	return true, ""
}

// nonLoginShells are shells that mean the account cannot interactively log
// in, so an empty password on such an account is not a login risk.
var nonLoginShells = map[string]bool{
	"":                  true,
	"/usr/sbin/nologin": true,
	"/sbin/nologin":     true,
	"/bin/false":        true,
	"/usr/bin/false":    true,
	"/bin/true":         true,
}

// Check parses the user databases and emits account-hygiene findings.
func (c *Checker) Check(_ context.Context, _ platform.Env) ([]model.Finding, error) {
	passwd, err := os.ReadFile(c.PasswdPath) //nolint:gosec // fixed system path
	if err != nil {
		return nil, err
	}

	loginShell := map[string]bool{} // username -> has an interactive login shell
	var rogueRoot []string
	for _, line := range strings.Split(string(passwd), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		name, uid, shell := fields[0], fields[2], fields[6]
		loginShell[name] = !nonLoginShells[strings.TrimSpace(shell)]
		if uid == "0" && name != "root" {
			rogueRoot = append(rogueRoot, name)
		}
	}

	var findings []model.Finding
	if len(rogueRoot) > 0 {
		sort.Strings(rogueRoot)
		findings = append(findings, model.NewFinding(
			"accounts.uid0", "Non-root account with root's UID (0)",
			model.SeverityCritical, model.SourceAccounts, model.RemediationManual,
			model.WithDescription("An account other than 'root' has UID 0, which gives it full root privileges under a different name. This is a common backdoor and almost never legitimate."),
			model.WithHowToFix("Verify why "+strings.Join(rogueRoot, ", ")+" has UID 0. If it is not intentional, remove the account (`userdel`) or give it a normal, unique UID. Grant admin rights via sudo, not UID 0."),
			model.WithEvidence("accounts", strings.Join(rogueRoot, ", ")),
		))
	}

	// The empty-password check needs /etc/shadow, which is root-only. If it
	// is unreadable, skip just this check rather than failing the domain.
	shadow, err := os.ReadFile(c.ShadowPath) //nolint:gosec // fixed system path
	if err != nil {
		return findings, nil
	}
	var passwordless []string
	for _, line := range strings.Split(string(shadow), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 2 {
			continue
		}
		name, hash := fields[0], fields[1]
		if hash == "" && loginShell[name] {
			passwordless = append(passwordless, name)
		}
	}
	if len(passwordless) > 0 {
		sort.Strings(passwordless)
		findings = append(findings, model.NewFinding(
			"accounts.emptypassword", "Login account with an empty password",
			model.SeverityCritical, model.SourceAccounts, model.RemediationManual,
			model.WithDescription("A login account has no password set, so anyone who can reach a login prompt (console, SSH with password auth, su) can log in as that user with no credentials at all."),
			model.WithHowToFix("Set a strong password (`passwd "+passwordless[0]+"`) or lock the account (`passwd -l "+passwordless[0]+"`) if it should not log in. Affected: "+strings.Join(passwordless, ", ")+"."),
			model.WithEvidence("accounts", strings.Join(passwordless, ", ")),
		))
	}
	return findings, nil
}
