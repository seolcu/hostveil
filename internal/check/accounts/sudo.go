package accounts

import (
	"context"
	"errors"
	"slices"
	"sort"
	"strings"

	"github.com/seolcu/hostveil/internal/platform"
)

// sudoListArgv asks sudo what one user may actually run.
//
// The alternative is parsing /etc/sudoers and /etc/sudoers.d ourselves, and
// this domain is exactly where that goes wrong. sudoers is a layered
// configuration with an owner: it has User_Alias, Cmnd_Alias and Runas_Alias
// indirection, group specs (%sudo, %wheel) that resolve through nsswitch and
// can come from LDAP rather than /etc/group, netgroups, #includedir ordering,
// and per-file skip rules for names containing a dot. Re-deriving the
// effective answer through all of that is the mistake internal/compose.Discover
// exists to demonstrate — ask the tool that owns the configuration, and take
// its answer.
//
// -U names the user, which needs root and is why the gap is reported when
// hostveil is not. -n never prompts: sudo as root does not ask, and a scanner
// that could block on a password prompt is a scanner that hangs.
func sudoListArgv(user string) []string {
	return []string{"sudo", "-n", "-l", "-U", user}
}

// sudoTags are the per-command tags sudoers allows in front of a command spec.
//
// They matter because the command has to be read past them, and because two of
// them switch the very thing being looked for: within one privilege line
// NOPASSWD applies from where it appears until a later PASSWD turns it back
// on, so `NOPASSWD: /bin/ls, PASSWD: ALL` grants unrestricted sudo *with* a
// password and must not be flagged.
//
// The list is sudoers' own vocabulary, and it is not translated — which is the
// reason this reads tags rather than the sentence around them. sudo's prose is
// gettext-translated in dozens of locales; platform.DefaultRunner pins LC_ALL=C
// so the prose would hold, but a parser that does not depend on it cannot be
// broken by a host that reaches this code another way.
var sudoTags = []string{
	"NOPASSWD", "PASSWD", "NOEXEC", "EXEC", "SETENV", "NOSETENV",
	"LOG_INPUT", "NOLOG_INPUT", "LOG_OUTPUT", "NOLOG_OUTPUT",
	"FOLLOW", "NOFOLLOW", "MAIL", "NOMAIL", "INTERCEPT", "NOINTERCEPT",
}

// grantsPasswordlessRoot reports whether `sudo -l` output for one user says
// that user can run anything, as anyone, without being asked for a password.
//
// Deliberately only the unrestricted case. A NOPASSWD rule on a named command
// is ordinary administration — a backup script, a monitoring hook — and it is
// not a path to root unless that command happens to be exploitable, which is a
// question a config reader cannot answer. Flagging every one of them would bury
// the case that is unambiguous: a password prompt standing between an account
// and root, removed.
func grantsPasswordlessRoot(out string) bool {
	// Defaults !authenticate turns the password off for every rule on the
	// host, and the privilege lines below carry no tag saying so. Reading only
	// the tags would call such a host clean while it is the most passwordless
	// arrangement sudoers can express. The token can come from nowhere else.
	noAuth := strings.Contains(out, "!authenticate")

	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		// A privilege line begins with the runas spec. That is also what
		// separates it from the Defaults block above it, whose entries are a
		// comma-separated list with no parenthesised prefix.
		if !strings.HasPrefix(line, "(") {
			continue
		}
		close := strings.Index(line, ")")
		if close < 0 {
			continue
		}
		if commandsAreUnrestricted(line[close+1:], noAuth) {
			return true
		}
	}
	return false
}

// commandsAreUnrestricted walks one privilege line's command list, carrying the
// NOPASSWD state across the commas the way sudoers does, and reports whether
// ALL is reachable without a password.
func commandsAreUnrestricted(spec string, nopasswd bool) bool {
	for _, entry := range strings.Split(spec, ",") {
		cmd := strings.TrimSpace(entry)
		// Strip every leading tag, updating the state as it goes. More than
		// one may stack: `NOPASSWD: SETENV: ALL` is a real spelling.
		for {
			tag, rest, found := strings.Cut(cmd, ":")
			tag = strings.TrimSpace(tag)
			if !found || !isSudoTag(tag) {
				break
			}
			switch tag {
			case "NOPASSWD":
				nopasswd = true
			case "PASSWD":
				nopasswd = false
			}
			cmd = strings.TrimSpace(rest)
		}
		if nopasswd && cmd == "ALL" {
			return true
		}
	}
	return false
}

func isSudoTag(s string) bool { return slices.Contains(sudoTags, s) }

// errNoSudo and errNotRoot are the two ways this half of the domain goes
// unexamined. They are values rather than strings because Check turns each
// into a different coverage reason, and a checker that could not tell them
// apart would have to write one sentence covering both.
var (
	errNoSudo  = errors.New("sudo is not installed")
	errNotRoot = errors.New("sudo will not answer for another user unless hostveil is root")
)

// askSudo runs one `sudo -l -U user`.
func askSudo(ctx context.Context, r platform.CommandRunner, user string) ([]byte, error) {
	argv := sudoListArgv(user)
	return r.Run(ctx, argv[0], argv[1:]...)
}

// passwordlessSudoers returns the login accounts sudo says can become root
// without a password.
//
// root is skipped: it is already root, so a rule letting it run anything
// without a password grants nothing it did not have, and reporting it would put
// a finding on every host that has sudo installed. An account that is root
// under another name is accounts.uid0's finding, not this one.
//
// The control run is the whole design of this function. `sudo -l -U someone`
// exits non-zero both for an account with no sudo rights — the ordinary case,
// and the answer we wanted — and for "a non-root user cannot use -U", and
// nothing in the status distinguishes them. Reading the message instead would
// mean parsing translated prose. So root is asked first, where the answer is
// known: on a host where hostveil can use -U at all, root can run anything.
// A failure there means the question was refused rather than answered, and
// every later failure would have been the same refusal — which is the
// difference between "no account has passwordless sudo" and "I never got to
// look", the two this domain exists to keep apart.
//
// The one host this misreads is one whose sudoers grants root nothing, where
// hostveil reports a coverage gap it does not have. That is the safe
// direction: a domain wrongly marked Degraded is visible, and a domain wrongly
// marked clean is the failure that produced a perfect CVE score on an
// unscanned host.
func passwordlessSudoers(ctx context.Context, r platform.CommandRunner, users []string) ([]string, error) {
	if _, err := r.LookPath("sudo"); err != nil {
		return nil, errNoSudo
	}
	if _, err := askSudo(ctx, r, "root"); err != nil {
		return nil, errNotRoot
	}
	var found []string
	for _, u := range users {
		if u == "root" {
			continue
		}
		out, err := askSudo(ctx, r, u)
		if err != nil {
			continue // no sudo rights at all
		}
		if grantsPasswordlessRoot(string(out)) {
			found = append(found, u)
		}
	}
	sort.Strings(found)
	return found, nil
}
