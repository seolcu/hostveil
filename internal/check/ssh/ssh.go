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
	f, err := os.Open(c.ConfigPath) //nolint:gosec // fixed system path
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
	cfg, unread, err := parseConfigFile(c.ConfigPath)
	if err != nil {
		return nil, err
	}
	findings := auditConfig(cfg, c.ConfigPath)
	if len(unread) > 0 {
		return findings, &check.PartialError{
			Reason: "could not read included sshd config: " + strings.Join(unread, ", ") +
				" — settings there may override what was scanned",
			Covered: cfg.filesRead,
			Total:   cfg.filesRead + len(unread),
		}
	}
	return findings, nil
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
func parseConfigFile(path string) (sshdConfig, []string, error) {
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
		return p.cfg, nil, err
	}
	p.visited[path] = true
	p.cfg.filesRead++
	p.parse(data, path, 0)
	return p.cfg, p.unread, nil
}

type includeParser struct {
	baseDir string
	cfg     sshdConfig
	visited map[string]bool
	unread  []string
	stopped bool // hit a Match block; everything after it is conditional
}

func (p *includeParser) parse(data []byte, path string, depth int) {
	sc := bufio.NewScanner(bytes.NewReader(data))
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
			model.SeverityCritical, model.SourceSSH, model.RemediationAuto,
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

	return out
}

func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return def
}
