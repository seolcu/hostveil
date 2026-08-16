// Package accounts implements a native host account-hygiene checker. Its
// question is who can become root and what stands in their way, and it asks it
// three times: a second account carrying root's UID, a login account with no
// password at all, and — through sudo itself rather than by reading sudoers —
// an account that can run anything as root without being asked for one.
//
// The first two come out of /etc/passwd and /etc/shadow. The third does not,
// on purpose: see sudoListArgv.
package accounts

import (
	"context"
	"errors"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/seolcu/hostveil/internal/check"
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

// Available requires a Linux host with a readable /etc/passwd. /etc/shadow
// may still be unreadable without root; Check handles that by running the
// passwd-only checks and reporting the domain Degraded, so the unchecked half
// is visible rather than scored as clean.
//
// The OS gate is not belt-and-braces around the file check, because the file
// is there on macOS. It is a stub — the account database is Open Directory —
// so the UID-0 scan passes against something that does not describe the host,
// and the missing /etc/shadow produces the Degraded reason "re-run with sudo",
// which cannot help: the file is not unreadable, it does not exist. Advice
// that cannot work is worse than a skip. See platform.AuditableOS.
func (c *Checker) Available(_ context.Context, _ platform.Env) (bool, string) {
	if ok, why := platform.AuditableOS(); !ok {
		return false, why + ", where " + c.PasswdPath + " does not describe the accounts"
	}
	f, err := os.Open(c.PasswdPath) // fixed system path
	if err != nil {
		return false, "cannot read " + c.PasswdPath
	}
	_ = f.Close()
	return true, ""
}

// Check parses the user databases and emits account-hygiene findings.
func (c *Checker) Check(ctx context.Context, env platform.Env) ([]model.Finding, error) {
	passwd, err := os.ReadFile(c.PasswdPath) // fixed system path
	if err != nil {
		return nil, err
	}

	// Three questions, and each can go unanswered on its own: the UID-0 scan
	// needs only /etc/passwd, the empty-password scan needs /etc/shadow, and
	// the sudo scan needs sudo installed and hostveil running as root. A
	// ledger rather than an early return, because a non-root scan misses two
	// of the three and reporting only the first would under-state what went
	// unexamined — see check.Coverage.
	var cov check.Coverage
	cov.Covered(1) // /etc/passwd was read, or there would be no findings at all

	loginShell := map[string]bool{} // username -> has an interactive login shell
	var logins []string
	var rogueRoot []string
	for _, line := range strings.Split(string(passwd), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		name, shell := fields[0], fields[6]
		// Asked through platform because the Docker daemon domain asks the
		// same question of docker-group members, and the two answers used to
		// differ: this one matched whole paths against a fixed list, so a
		// nologin at any other path — Arch's /usr/bin/nologin, NixOS's under
		// /run/current-system — read as an ordinary login shell.
		loginShell[name] = !platform.IsNonLoginShell(shell)
		if loginShell[name] {
			logins = append(logins, name)
		}
		// Compare the UID numerically: the kernel parses "00"/"000" as 0, so
		// a string compare against "0" would let a leading-zero UID-0
		// backdoor slip past the very check that exists to catch it.
		if uid, err := strconv.Atoi(strings.TrimSpace(fields[2])); err == nil && uid == 0 && name != "root" {
			rogueRoot = append(rogueRoot, name)
		}
	}

	var findings []model.Finding
	if len(rogueRoot) > 0 {
		sort.Strings(rogueRoot)
		findings = append(findings, model.NewFinding(
			"accounts.uid0", "Non-root account with root's UID (0)",
			model.SeverityHigh, model.SourceAccounts, model.RemediationManual,
			model.WithDescription("An account other than 'root' has UID 0, which gives it full root privileges under a different name. This is a common backdoor and almost never legitimate."),
			model.WithHowToFix("Verify why "+strings.Join(rogueRoot, ", ")+" has UID 0. If it is not intentional, remove the account (`userdel`) or give it a normal, unique UID. Grant admin rights via sudo, not UID 0."),
			model.WithEvidence("accounts", strings.Join(rogueRoot, ", ")),
		))
	}

	// The empty-password check needs /etc/shadow, which is root-only. Losing
	// it costs half the domain, so the result is Degraded — never clean.
	//
	// Returning nil here is the mistake this package exists to catch, made by
	// the checker itself: "could not read /etc/shadow" and "no account has an
	// empty password" score identically and mean opposite things. A non-root
	// scan reported full marks for account hygiene having never looked at a
	// single password, which is the same lie that once produced a perfect CVE
	// score on an unscanned host.
	shadow, err := os.ReadFile(c.ShadowPath) // fixed system path
	if err != nil {
		cov.Missed(1, "cannot read "+c.ShadowPath+
			" — did not check for accounts with an empty password; re-run with sudo")
	} else {
		cov.Covered(1)
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
				model.SeverityHigh, model.SourceAccounts, model.RemediationManual,
				model.WithDescription("A login account has no password set, so anyone who can reach a login prompt (console, SSH with password auth, su) can log in as that user with no credentials at all."),
				model.WithHowToFix("Set a strong password (`passwd "+passwordless[0]+"`) or lock the account (`passwd -l "+passwordless[0]+"`) if it should not log in. Affected: "+strings.Join(passwordless, ", ")+"."),
				model.WithEvidence("accounts", strings.Join(passwordless, ", ")),
			))
		}
	}

	// Who can become root, and what stands in their way. An empty password is
	// the classic version of that question and sudo is the one people actually
	// hit: a NOPASSWD rule turns "holds this account's SSH key" into "is root",
	// with nothing in between.
	//
	// A host with no sudo at all is covered rather than missed. That is the
	// direction dockerd's config merge got wrong: an absent file is a complete
	// answer about that file, and no sudo binary means no sudo rule can be
	// granting anyone anything. Calling it a gap would mark every sudo-less
	// host Degraded for a question that has an answer.
	sudoers, err := passwordlessSudoers(ctx, env.Runner, logins)
	switch {
	case errors.Is(err, errNoSudo):
		cov.Covered(1)
	case errors.Is(err, errNotRoot):
		cov.Missed(1, "sudo will not report another account's privileges unless hostveil is root — "+
			"did not check whether any account can become root without a password; re-run with sudo")
	default:
		cov.Covered(1)
		if len(sudoers) > 0 {
			findings = append(findings, model.NewFinding(
				"accounts.sudo-nopasswd", "An account can become root without a password",
				model.SeverityMedium, model.SourceAccounts, model.RemediationManual,
				model.WithDescription("A sudo rule lets this account run any command as root without being asked for a password. That removes the last step between holding the account and holding the host: anyone who gets its SSH key, or a shell through a service it runs, is root immediately rather than needing its password as well. "+
					"Cloud and VM images ship this on purpose so the first login works, and it is usually still there years later."),
				model.WithHowToFix("Run `sudo visudo` (or `sudo visudo -f /etc/sudoers.d/<file>` for a drop-in) and change the rule for "+strings.Join(sudoers, ", ")+" from `NOPASSWD: ALL` to `ALL`, so sudo asks for the account's password. "+
					"Set that password first with `passwd "+sudoers[0]+"` and confirm it works in a second session: images that ship NOPASSWD often ship no password either, and an account with neither cannot use sudo at all once the rule is gone. "+
					"Keep a root shell open until you have checked."),
				model.WithEvidence("accounts", strings.Join(sudoers, ", ")),
			))
		}
	}

	return findings, cov.Err()
}
