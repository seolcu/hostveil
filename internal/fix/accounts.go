package fix

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/seolcu/hostveil/internal/model"
)

func registerAccounts(r *Registry) {
	r.Register("accounts.password-rounds", buildLoginDefaults("Harden password hashing rounds",
		"Raises the SHA-512 rounds used to hash new or changed passwords, slowing an offline "+
			"dictionary or brute-force attempt against a stolen /etc/shadow by roughly the same factor.",
		[]loginDefault{{"SHA_CRYPT_MIN_ROUNDS", "5000"}, {"SHA_CRYPT_MAX_ROUNDS", "10000"}}))
	r.Register("accounts.default-umask", buildLoginDefaults("Set the default umask to 027",
		"New files a user creates default to unreadable by other accounts on the box, closing the "+
			"easiest way a stray world-readable file leaks something it shouldn't.",
		[]loginDefault{{"UMASK", "027"}}))
	r.Register("accounts.password-aging", buildLoginDefaults("Harden password aging defaults",
		"Forces credentials to actually expire and blocks changing a password back to itself "+
			"immediately, so a leaked password has a shelf life instead of being valid forever.",
		[]loginDefault{{"PASS_MIN_DAYS", "1"}, {"PASS_MAX_DAYS", "365"}}))
	r.Register("accounts.core-dumps", buildCoreDumpLimit)
	r.Register("accounts.local-banner", buildAccessBanner)
	r.Register("accounts.remote-banner", buildAccessBanner)
	r.Register("accounts.emptypassword", buildLockEmptyPasswordAccount)
}

// buildLockEmptyPasswordAccount locks the first account the finding names
// rather than setting a new password: hostveil has no way to collect one
// from the operator, and inventing a credential is the same mistake the
// per-CVE fixes were declined for. `passwd -l` is exec, so EffectiveKind
// floors this to Review whatever it declares here — and it should, since the
// account it locks may be the operator's only way to reach the machine
// (console, su) and /etc/shadow does not say which this is. That risk is
// disclosed via Warning and left to the operator, the same shape
// ssh.passwordauth and firewall.inactive already carry.
//
// Only the first account when several are affected. Locking is per-account
// exec with no shared state, unlike firewall.inactive's ports which all need
// to stay open together — batching several accounts into one action would
// raise the blast radius of a single Fix for no offsetting benefit. The
// remaining accounts are re-detected on the next scan.
func buildLockEmptyPasswordAccount(f model.Finding) (Fix, error) {
	accounts := strings.Split(f.Evidence["accounts"], ", ")
	if len(accounts) == 0 || accounts[0] == "" {
		return Fix{}, fmt.Errorf("finding %s names no accounts", f.ID)
	}
	account := accounts[0]

	return Fix{
		FindingID: f.ID,
		Label:     "Lock the empty-password account " + account,
		Kind:      model.RemediationAuto, // one action; exec floors it to Review
		Actions: []Action{{
			Label: "Lock " + account + " with `passwd -l`",
			Benefit: "Closes the one account whose password prompt currently succeeds for anyone who " +
				"tries it, including a stranger who has never touched this host before.",
			Warning: "If " + account + " is your only way to reach this machine locally (console, su) " +
				"and it has no other credential, locking it removes that access. Confirm you have another " +
				"route in — an SSH key, a different sudo-capable account — before applying. The remote SSH " +
				"path is already closed by ssh.emptypasswords; this only closes the local one.",
			Kind:     ActionExec,
			Commands: [][]string{{"passwd", "-l", account}},
		}},
	}, nil
}

func buildCoreDumpLimit(f model.Finding) (Fix, error) {
	path := f.Evidence["config"]
	if path == "" {
		return Fix{}, fmt.Errorf("finding %s names no limits path", f.ID)
	}
	return Fix{Label: "Disable core dumps through PAM limits", Kind: model.RemediationAuto, Actions: []Action{{
		Label: "Set a hard core-size limit of zero",
		Benefit: "Stops a crashed privileged process writing a core file to disk — the easiest place " +
			"a live secret in memory (a password, a key) ends up sitting in plaintext after a crash.",
		Kind: ActionEdit, Path: path, Transform: func(in []byte) ([]byte, error) {
			if hasCoreLimit(in) {
				return in, nil
			}
			out := append([]byte(nil), bytes.TrimRight(in, "\n")...)
			if len(out) > 0 {
				out = append(out, '\n')
			}
			return append(out, []byte("* hard core 0\n")...), nil
		}}}}, nil
}

func hasCoreLimit(data []byte) bool {
	for _, line := range bytes.Split(data, []byte("\n")) {
		fields := bytes.Fields(bytes.SplitN(line, []byte("#"), 2)[0])
		if len(fields) == 4 && bytes.Equal(fields[0], []byte("*")) && bytes.Equal(fields[1], []byte("hard")) && bytes.Equal(fields[2], []byte("core")) && bytes.Equal(fields[3], []byte("0")) {
			return true
		}
	}
	return false
}

type loginDefault struct{ key, value string }

func buildLoginDefaults(label, benefit string, values []loginDefault) Builder {
	return func(f model.Finding) (Fix, error) {
		path := f.Evidence["config"]
		if path == "" {
			return Fix{}, fmt.Errorf("finding %s names no login.defs path", f.ID)
		}
		return Fix{Label: label, Kind: model.RemediationAuto, Actions: []Action{{Label: label, Benefit: benefit, Kind: ActionEdit, Path: path, Transform: func(in []byte) ([]byte, error) {
			out := in
			for _, setting := range values {
				re := regexp.MustCompile(`(?m)^[ \t]*#?[ \t]*` + regexp.QuoteMeta(setting.key) + `[ \t]+.*$`)
				line := []byte(setting.key + " " + setting.value)
				if re.Match(out) {
					out = re.ReplaceAll(out, line)
				} else {
					out = append(bytes.TrimRight(out, "\n"), append([]byte("\n"), append(line, '\n')...)...)
				}
			}
			return out, nil
		}}}}, nil
	}
}

const accessWarning = "WARNING: Authorized access only. Activity may be monitored and recorded. Unauthorized use is prohibited and may be reported."

func buildAccessBanner(f model.Finding) (Fix, error) {
	path := f.Evidence["config"]
	if path == "" {
		return Fix{}, fmt.Errorf("finding %s names no banner path", f.ID)
	}
	return Fix{Label: "Add a pre-login access warning", Kind: model.RemediationAuto, Actions: []Action{{
		Label: "Append the standard access warning",
		Benefit: "Puts a legal notice in front of anyone who logs into this host, local or remote, which " +
			"several jurisdictions require before monitoring or logging a session can be used as evidence " +
			"against an intruder.",
		Warning: "Have counsel or the system owner approve login-banner wording for this organization.",
		Kind:    ActionEdit, Path: path, CreateIfMissing: true, Transform: func(in []byte) ([]byte, error) {
			if bytes.Contains(bytes.ToLower(in), []byte("authorized access only")) {
				return in, nil
			}
			out := append([]byte(nil), bytes.TrimRight(in, "\n")...)
			if len(out) > 0 {
				out = append(out, '\n')
			}
			return append(out, []byte(accessWarning+"\n")...), nil
		}}}}, nil
}
