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
	// LoginDefsPath and banner paths are overridable for tests. Empty paths
	// disable the corresponding baseline check for focused fixtures.
	LoginDefsPath string
	IssuePath     string
	IssueNetPath  string
	LimitsPath    string
}

// New returns an accounts checker reading the standard system databases.
func New() *Checker {
	return &Checker{PasswdPath: "/etc/passwd", ShadowPath: "/etc/shadow", LoginDefsPath: "/etc/login.defs", IssuePath: "/etc/issue", IssueNetPath: "/etc/issue.net", LimitsPath: "/etc/security/limits.conf"}
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
	uids := map[int][]string{}
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
		if uid, err := strconv.Atoi(strings.TrimSpace(fields[2])); err == nil {
			uids[uid] = append(uids[uid], name)
			if uid == 0 && name != "root" {
				rogueRoot = append(rogueRoot, name)
			}
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
	var duplicateUIDs []string
	for uid, names := range uids {
		if uid == 0 || len(names) < 2 {
			continue
		}
		sort.Strings(names)
		duplicateUIDs = append(duplicateUIDs, strconv.Itoa(uid)+": "+strings.Join(names, ", "))
	}
	if len(duplicateUIDs) > 0 {
		sort.Strings(duplicateUIDs)
		findings = append(findings, model.NewFinding("accounts.duplicate-uid", "Multiple accounts share the same UID", model.SeverityMedium, model.SourceAccounts, model.RemediationManual,
			model.WithDescription("Linux authorizes a process by numeric UID, not account name. Accounts sharing one UID are indistinguishable to file ownership and audit logs."),
			model.WithHowToFix("Assign every affected account a unique UID with `usermod -u`, then carefully migrate files owned by the old UID."),
			model.WithEvidence("uids", strings.Join(duplicateUIDs, model.EvidenceSeparator))))
	}

	if c.LoginDefsPath != "" {
		if data, err := os.ReadFile(c.LoginDefsPath); err == nil {
			defs := loginDefaults(data)
			minRounds := atoiOrZero(defs["SHA_CRYPT_MIN_ROUNDS"])
			maxRounds := atoiOrZero(defs["SHA_CRYPT_MAX_ROUNDS"])
			if minRounds < 5000 || maxRounds < 5000 {
				findings = append(findings, model.NewFinding("accounts.password-rounds", "Password hashing rounds are not hardened", model.SeverityLow, model.SourceAccounts, model.RemediationAuto,
					model.WithDescription("Explicit SHA-crypt rounds make offline password guessing more expensive for hashes created after this setting is applied."),
					model.WithHowToFix("Set SHA_CRYPT_MIN_ROUNDS and SHA_CRYPT_MAX_ROUNDS to at least 5000 in "+c.LoginDefsPath+"."), model.WithEvidence("config", c.LoginDefsPath)))
			}
			if mask := defs["UMASK"]; mask != "027" && mask != "077" && mask != "0027" && mask != "0077" {
				findings = append(findings, model.NewFinding("accounts.default-umask", "New files default to broad permissions", model.SeverityLow, model.SourceAccounts, model.RemediationReview,
					model.WithDescription("A 027 default umask prevents unrelated local users from reading newly created files while preserving access for the owner's group."),
					model.WithHowToFix("Set UMASK 027 in "+c.LoginDefsPath+" after checking workflows that rely on world-readable files."), model.WithEvidence("config", c.LoginDefsPath), model.WithEvidence("value", mask)))
			}
			minDays := atoiOrZero(defs["PASS_MIN_DAYS"])
			maxDays := atoiOrZero(defs["PASS_MAX_DAYS"])
			if minDays < 1 || maxDays == 0 || maxDays > 365 {
				findings = append(findings, model.NewFinding("accounts.password-aging", "Password aging defaults are too permissive", model.SeverityLow, model.SourceAccounts, model.RemediationAuto,
					model.WithDescription("New local passwords can be changed repeatedly without delay and may remain valid indefinitely, weakening rotation and password-history controls."),
					model.WithHowToFix("Set PASS_MIN_DAYS to 1 and PASS_MAX_DAYS to 365 in "+c.LoginDefsPath+"."), model.WithEvidence("config", c.LoginDefsPath)))
			}
		}
	}
	if c.LimitsPath != "" {
		if data, err := os.ReadFile(c.LimitsPath); err == nil && !hasCoreLimit(data) {
			findings = append(findings, model.NewFinding("accounts.core-dumps", "Core dumps are not explicitly disabled", model.SeverityLow, model.SourceAccounts, model.RemediationAuto,
				model.WithDescription("Core files can preserve credentials and other process memory after a crash where local users or support tooling may expose them."),
				model.WithHowToFix("Set a hard core-size limit of zero in "+c.LimitsPath+"."), model.WithEvidence("config", c.LimitsPath)))
		}
	}
	for _, banner := range []struct{ id, path string }{{"accounts.local-banner", c.IssuePath}, {"accounts.remote-banner", c.IssueNetPath}} {
		if banner.path == "" {
			continue
		}
		data, err := os.ReadFile(banner.path)
		if err == nil && hasAccessWarning(string(data)) {
			continue
		}
		findings = append(findings, model.NewFinding(banner.id, "Login warning does not discourage unauthorized access", model.SeverityLow, model.SourceAccounts, model.RemediationReview,
			model.WithDescription("A clear pre-login warning establishes that access is restricted and that activity may be monitored before credentials are accepted."),
			model.WithHowToFix("Add an organization-approved access warning to "+banner.path+"."), model.WithEvidence("config", banner.path)))
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
		var passwordless, weakHashes []string
		for _, line := range strings.Split(string(shadow), "\n") {
			fields := strings.Split(line, ":")
			if len(fields) < 2 {
				continue
			}
			name, hash := fields[0], fields[1]
			if hash == "" && loginShell[name] {
				passwordless = append(passwordless, name)
			}
			if loginShell[name] && (strings.HasPrefix(hash, "$1$") || (!strings.HasPrefix(hash, "$") && hash != "" && hash != "!" && hash != "*" && !strings.HasPrefix(hash, "!"))) {
				weakHashes = append(weakHashes, name)
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
		if len(weakHashes) > 0 {
			sort.Strings(weakHashes)
			findings = append(findings, model.NewFinding("accounts.weak-password-hash", "A login account uses a weak password hash", model.SeverityMedium, model.SourceAccounts, model.RemediationManual,
				model.WithDescription("DES and MD5 password hashes are fast to crack with modern hardware and should not protect an interactive account."),
				model.WithHowToFix("Reset the affected account passwords after configuring yescrypt or SHA-512 as the system password hashing method."),
				model.WithEvidence("accounts", strings.Join(weakHashes, ", "))))
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
		cov.Missed(1, "sudo will not report another account's privileges unless Hostveil is root — "+
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

func loginDefaults(data []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			out[fields[0]] = fields[1]
		}
	}
	return out
}

func atoiOrZero(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func hasAccessWarning(s string) bool {
	s = strings.ToLower(s)
	words := []string{"authorized", "access", "monitor", "prohibited", "unauthorized"}
	for _, word := range words {
		if !strings.Contains(s, word) {
			return false
		}
	}
	return true
}

func hasCoreLimit(data []byte) bool {
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(strings.SplitN(line, "#", 2)[0])
		if len(fields) == 4 && fields[0] == "*" && fields[1] == "hard" && fields[2] == "core" && fields[3] == "0" {
			return true
		}
	}
	return false
}
