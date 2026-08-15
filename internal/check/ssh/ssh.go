// Package ssh implements a native SSH-hardening checker. It parses
// sshd_config directly (no external tool) and flags the settings most
// likely to expose a self-hosted server: root password login, empty
// passwords, password authentication, and weak brute-force limits.
package ssh

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// Checker audits the OpenSSH server configuration.
type Checker struct {
	// ConfigPath is the sshd_config to read; overridable for tests.
	ConfigPath string
}

// New returns an SSH checker reading the system sshd_config.
func New() *Checker { return &Checker{ConfigPath: "/etc/ssh/sshd_config"} }

// Source identifies the SSH domain.
func (*Checker) Source() model.Source { return model.SourceSSH }

// Available requires sshd_config to exist and be readable. A missing file
// means no SSH server to audit; a permission error means the tool was run
// without the privileges needed to read it — both are clean skips with an
// actionable reason, never a scan error.
func (c *Checker) Available(_ context.Context, _ platform.Env) (bool, string) {
	f, err := os.Open(c.ConfigPath) // fixed system path
	if err != nil {
		switch {
		case os.IsNotExist(err):
			return false, "OpenSSH server not configured (no sshd_config)"
		case os.IsPermission(err):
			return false, "cannot read sshd_config without root — re-run with sudo to scan SSH"
		default:
			return false, "cannot read sshd_config: " + err.Error()
		}
	}
	_ = f.Close()
	return true, ""
}

// Check parses sshd_config and applies the hardening rules. Include files
// that exist but cannot be read make the audit partial, not wrong: the
// findings we did derive are real, but a directive in the unread file could
// override any of them, so the domain is reported Degraded rather than
// clean.
func (c *Checker) Check(_ context.Context, _ platform.Env) ([]model.Finding, error) {
	cfg, gaps, err := parseConfigFile(c.ConfigPath)
	if err != nil {
		return nil, err
	}
	findings := auditConfig(cfg, c.ConfigPath)

	// A ledger rather than a return-on-first-gap, because this domain now has
	// two ways to fall short and a config can hit both at once: an include
	// that could not be read, and a Match block the parse stopped at. Deciding
	// at the point a gap is found is how a checker keeps one and discards the
	// other, which is the mistake check.Coverage exists to make unavailable.
	var cov check.Coverage
	cov.Covered(cfg.filesRead)
	if len(gaps.unread) > 0 {
		cov.Missed(len(gaps.unread), "could not read included sshd config: "+
			strings.Join(gaps.unread, ", ")+" — settings there may override what was scanned")
	}
	if gaps.matchIn != "" {
		// Zero units: a Match block has no denominator. The directives inside
		// it are precisely the ones that were not counted, so there is no
		// number to add without inventing one.
		cov.Missed(0, "stopped at a Match block in "+gaps.matchIn+
			" — directives inside conditional blocks were not evaluated, and one there may "+
			"re-enable what was scanned as disabled")
	}
	return findings, cov.Err()
}

// coverageGaps is what the parse could not account for: files it could not
// read, and the file it stopped at.
type coverageGaps struct {
	unread  []string
	matchIn string
}

// sshdConfig is the effective configuration: the first value seen for each
// keyword, plus the file that value came from. The origin matters as much
// as the value — a fix has to edit the file that actually wins, not the
// top-level sshd_config, or it writes a directive that stays overridden.
type sshdConfig struct {
	values    map[string]string
	origin    map[string]string
	filesRead int
}

// maxIncludeDepth mirrors OpenSSH's own nesting limit.
const maxIncludeDepth = 16

// parseConfigFile parses sshd_config, following Include directives, into
// effective directive values. sshd uses the first value obtained for each
// keyword and expands an Include in place, so a file included at the top —
// which is how Debian and Ubuntu ship it, and how cloud images inject
// their own defaults — wins over the lines below it. Reading only the
// top-level file therefore both misses directives and reports ones that
// are overridden.
//
// Match blocks introduce conditional overrides we cannot evaluate
// statically, so parsing stops at the first Match, in whichever file it
// appears. The returned slice names include files that matched a glob but
// could not be read.
func parseConfigFile(path string) (sshdConfig, coverageGaps, error) {
	p := &includeParser{
		baseDir: filepath.Dir(path),
		cfg: sshdConfig{
			values: map[string]string{},
			origin: map[string]string{},
		},
		visited: map[string]bool{},
	}
	data, err := os.ReadFile(path) //nolint:gosec // caller-supplied fixed system path
	if err != nil {
		return p.cfg, coverageGaps{}, err
	}
	p.visited[path] = true
	p.cfg.filesRead++
	p.parse(data, path, 0)
	return p.cfg, coverageGaps{unread: p.unread, matchIn: p.matchIn}, nil
}

type includeParser struct {
	baseDir string
	cfg     sshdConfig
	visited map[string]bool
	unread  []string
	stopped bool // hit a Match block; everything after it is conditional
	// matchIn is the file the first Match block was found in, and it is the
	// whole reason stopped is not enough on its own.
	//
	// Stopping there is right: sshd applies a Match block only to connections
	// it matches, so a directive under one does not describe the host the way
	// a global directive does. What is wrong is stopping silently. Check
	// already reports an include it could not READ as partial coverage,
	// reasoning that "a directive in the unread file could override any of
	// them" — and that is exactly the situation here, from the same parser,
	// about directives this one chose not to read.
	//
	// `Match Address 0.0.0.0/0` followed by `PasswordAuthentication yes` puts
	// passwords back for every connection on the host, and the domain reported
	// clean and not degraded. That is "I could not look" passing for "nothing
	// there", which is the one thing a checker here must never do.
	matchIn string
}

// parse reads one config file's directives into the effective config.
//
// A scanner error — in practice bufio.ErrTooLong, a line over 64 KiB — stops
// the read partway with no error returned anywhere, so every directive after
// that point read as unset and the compiled-in default silently won the
// audit. PermitRootLogin is the one that matters: unset audits as the
// default, so a truncated parse could report a hardened host as exposed, or
// an exposed one as fine, depending on which side of the long line the
// directive sat. It is recorded as a file we could not fully read, which is
// what it is, and rides the same PartialError the unreadable-include case
// already uses.
func (p *includeParser) parse(data []byte, path string, depth int) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	defer func() {
		if sc.Err() != nil {
			// The caller counted this file as read before handing it over;
			// take that back, so Covered/Total describes what was actually
			// covered rather than crediting a file we only half-parsed.
			p.cfg.filesRead--
			p.unread = append(p.unread, path)
		}
	}()
	for sc.Scan() {
		if p.stopped {
			return
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := splitDirective(line)
		if !ok {
			continue
		}
		switch strings.ToLower(key) {
		case "match":
			p.stopped = true
			p.matchIn = path
			return
		case "include":
			p.include(val, depth)
		default:
			p.set(strings.ToLower(key), val, path)
		}
	}
}

func (p *includeParser) set(key, val, path string) {
	if _, seen := p.cfg.values[key]; seen {
		return // sshd keeps the first value obtained
	}
	p.cfg.values[key] = val
	p.cfg.origin[key] = path
}

// include expands one Include directive in place. A directive may carry
// several patterns; each is expanded in turn, and glob matches are read in
// sorted order, which is the order sshd uses.
func (p *includeParser) include(val string, depth int) {
	if depth >= maxIncludeDepth {
		return
	}
	for _, pattern := range strings.Fields(val) {
		if !filepath.IsAbs(pattern) {
			pattern = filepath.Join(p.baseDir, pattern)
		}
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue // malformed pattern; sshd would reject the config outright
		}
		sort.Strings(matches)
		for _, m := range matches {
			if p.stopped {
				return
			}
			p.readInto(m, depth)
		}
	}
}

func (p *includeParser) readInto(path string, depth int) {
	if p.visited[path] {
		return // cycle, or the same file reached by two patterns
	}
	p.visited[path] = true

	// G703: path came from expanding an Include glob inside sshd_config,
	// which is a root-owned file this checker only reads. An operator who
	// can write it can already do anything this process could.
	//nolint:gosec // G703: from sshd_config's own Include, read-only
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return // sshd ignores directories matched by a glob
	}
	data, err := os.ReadFile(path) //nolint:gosec // path came from the config's own Include glob
	if err != nil {
		p.unread = append(p.unread, path)
		return
	}
	p.cfg.filesRead++
	p.parse(data, path, depth+1)
}

func splitDirective(line string) (key, val string, ok bool) {
	// Directives are "Keyword value", optionally with '='.
	line = strings.TrimSpace(strings.ReplaceAll(line, "=", " "))
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", "", false
	}
	return fields[0], strings.Join(fields[1:], " "), true
}

func effective(cfg sshdConfig, key, def string) string {
	if v, ok := cfg.values[strings.ToLower(key)]; ok {
		return strings.ToLower(v)
	}
	return def
}

// configFor names the file a fix must edit to change key. When the
// directive is set, that is the file it is set in — editing anywhere else
// leaves the winning value in place. When it is absent and the finding
// rests on sshd's compiled-in default, the top-level file is the right
// place to add it.
func configFor(cfg sshdConfig, mainPath, key string) model.FindingOption {
	if origin, ok := cfg.origin[strings.ToLower(key)]; ok {
		return model.WithEvidence("config", origin)
	}
	return model.WithEvidence("config", mainPath)
}

func auditConfig(cfg sshdConfig, path string) []model.Finding {
	var out []model.Finding

	if effective(cfg, "PermitRootLogin", "prohibit-password") == "yes" {
		out = append(out, model.NewFinding("ssh.rootlogin", "SSH permits root login with a password",
			model.SeverityHigh, model.SourceSSH, model.RemediationReview,
			model.WithDescription("Allowing root to log in over SSH with a password makes the most powerful account a direct brute-force target. A single guessed password is a full host compromise."),
			model.WithHowToFix("Set `PermitRootLogin prohibit-password` (key-only) or `no`, and log in as a normal user with sudo instead."),
			configFor(cfg, path, "PermitRootLogin")))
	}

	if effective(cfg, "PermitEmptyPasswords", "no") == "yes" {
		out = append(out, model.NewFinding("ssh.emptypasswords", "SSH allows empty passwords",
			model.SeverityHigh, model.SourceSSH, model.RemediationAuto,
			model.WithDescription("Accounts with no password could be logged into by anyone. This is almost never intended and is trivially exploitable."),
			model.WithHowToFix("Set `PermitEmptyPasswords no` in sshd_config."),
			configFor(cfg, path, "PermitEmptyPasswords")))
	}

	if effective(cfg, "PasswordAuthentication", "yes") == "yes" {
		out = append(out, model.NewFinding("ssh.passwordauth", "SSH allows password authentication",
			model.SeverityMedium, model.SourceSSH, model.RemediationReview,
			model.WithDescription("Password logins are vulnerable to brute-force and credential-stuffing attacks that key-based authentication is immune to. Bots constantly scan the internet for SSH servers accepting passwords."),
			model.WithHowToFix("Set up an SSH key, then set `PasswordAuthentication no`. Make sure your key works before disabling passwords so you do not lock yourself out."),
			configFor(cfg, path, "PasswordAuthentication")))
	}

	if tries := atoiDefault(effective(cfg, "MaxAuthTries", "6"), 6); tries > 6 {
		out = append(out, model.NewFinding("ssh.maxauthtries", "SSH allows many authentication attempts per connection",
			model.SeverityLow, model.SourceSSH, model.RemediationAuto,
			model.WithDescription("A high MaxAuthTries lets an attacker try many passwords per connection, speeding up brute-force attacks."),
			model.WithHowToFix("Lower `MaxAuthTries` to 3 or 4."),
			model.WithEvidence("value", strconv.Itoa(tries)), configFor(cfg, path, "MaxAuthTries")))
	}

	if effective(cfg, "X11Forwarding", "no") == "yes" {
		out = append(out, model.NewFinding("ssh.x11forwarding", "SSH X11 forwarding is enabled",
			model.SeverityLow, model.SourceSSH, model.RemediationAuto,
			model.WithDescription("X11 forwarding widens the attack surface and is rarely needed on a headless server."),
			model.WithHowToFix("Set `X11Forwarding no` unless you specifically forward graphical applications."),
			configFor(cfg, path, "X11Forwarding")))
	}

	// sshd's own default is 120 seconds, so this fires on an untouched
	// config — deliberately, like ssh.passwordauth. The fix is Auto because
	// shortening the window cannot lock anyone out: it only bounds how long
	// an unauthenticated connection may sit there. 0 means no limit at all.
	grace := effective(cfg, "LoginGraceTime", "120")
	if secs, ok := parseSSHDuration(grace); ok && (secs == 0 || secs > 60) {
		out = append(out, model.NewFinding("ssh.logingracetime", "SSH keeps unauthenticated connections open too long",
			model.SeverityLow, model.SourceSSH, model.RemediationAuto,
			model.WithDescription("LoginGraceTime is how long sshd waits for a connection to authenticate before dropping it. A long (or unlimited) window lets scanning bots hold many half-open connections and gives every brute-force attempt more room."),
			model.WithHowToFix("Set `LoginGraceTime 60` or lower."),
			model.WithEvidence("value", grace), configFor(cfg, path, "LoginGraceTime")))
	}

	if v := effective(cfg, "GatewayPorts", "no"); v == "yes" || v == "clientspecified" {
		out = append(out, model.NewFinding("ssh.gatewayports", "SSH exposes remote-forwarded ports to the network",
			model.SeverityMedium, model.SourceSSH, model.RemediationReview,
			model.WithDescription("With GatewayPorts enabled, a port forwarded with `ssh -R` listens on all interfaces instead of loopback, so anyone who can reach this host can use the tunnel — effectively publishing whatever the tunnel reaches."),
			model.WithHowToFix("Set `GatewayPorts no` so remote-forwarded ports bind to loopback only. If a tunnel genuinely must be public, front it with a reverse proxy that authenticates."),
			model.WithEvidence("value", v), configFor(cfg, path, "GatewayPorts")))
	}

	if effective(cfg, "HostbasedAuthentication", "no") == "yes" {
		out = append(out, model.NewFinding("ssh.hostbasedauth", "SSH trusts other hosts' identities for login",
			model.SeverityMedium, model.SourceSSH, model.RemediationReview,
			model.WithDescription("Host-based authentication lets users log in because of which machine they connect from, without any per-user credential. Compromising one trusted host then opens this one."),
			model.WithHowToFix("Set `HostbasedAuthentication no` and use per-user SSH keys instead."),
			configFor(cfg, path, "HostbasedAuthentication")))
	}

	// The contradiction case only: PasswordAuthentication no is meant to end
	// password guessing, but keyboard-interactive runs the same PAM password
	// prompt through a different door. KbdInteractiveAuthentication defaults
	// to yes, and ChallengeResponseAuthentication is its pre-8.7 alias — an
	// operator who disabled either one has already closed the door.
	kbdKey := "KbdInteractiveAuthentication"
	kbd := effective(cfg, kbdKey, "")
	if kbd == "" {
		if v := effective(cfg, "ChallengeResponseAuthentication", ""); v != "" {
			kbdKey = "ChallengeResponseAuthentication"
			kbd = v
		} else {
			kbd = "yes"
		}
	}
	if kbd == "yes" && effective(cfg, "PasswordAuthentication", "yes") == "no" {
		out = append(out, model.NewFinding("ssh.kbdinteractive", "SSH still accepts interactive password prompts",
			model.SeverityMedium, model.SourceSSH, model.RemediationReview,
			model.WithDescription("PasswordAuthentication is off, but keyboard-interactive authentication is still on — and on most systems it asks PAM for the very same password. The brute-force protection you configured is not actually in force."),
			model.WithHowToFix("Set `KbdInteractiveAuthentication no`. Careful: PAM-based one-time codes (2FA prompts) also use this mechanism, so keep it if your logins go through one."),
			model.WithEvidence("directive", kbdKey), configFor(cfg, path, kbdKey)))
	}

	return out
}

// parseSSHDuration parses sshd's time format: a bare number is seconds, and
// qualified values chain quantity[unit] pairs ("90", "2m", "1h30m"). It
// returns false for anything else, and a false parse produces no finding —
// sshd -t is the authority on validity, not this checker.
func parseSSHDuration(s string) (seconds int, ok bool) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0, false
	}
	total, num, haveDigits := 0, 0, false
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			num = num*10 + int(c-'0')
			haveDigits = true
		case c == 's' || c == 'm' || c == 'h' || c == 'd' || c == 'w':
			if !haveDigits {
				return 0, false
			}
			mult := map[byte]int{'s': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 604800}[c]
			total += num * mult
			num, haveDigits = 0, false
		default:
			return 0, false
		}
	}
	if haveDigits {
		total += num
	}
	return total, true
}

func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return def
}
