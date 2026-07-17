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
	"strconv"
	"strings"

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

// Check parses sshd_config and applies the hardening rules.
func (c *Checker) Check(_ context.Context, _ platform.Env) ([]model.Finding, error) {
	data, err := os.ReadFile(c.ConfigPath) //nolint:gosec // fixed system path
	if err != nil {
		return nil, err
	}
	return auditConfig(parseConfig(data), c.ConfigPath), nil
}

// parseConfig parses sshd_config into effective directive values. sshd
// uses the first value obtained for each keyword, so we keep the first
// occurrence. Match blocks introduce conditional overrides we cannot
// evaluate statically, so parsing stops at the first Match.
func parseConfig(data []byte) map[string]string {
	cfg := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := splitDirective(line)
		if !ok {
			continue
		}
		lkey := strings.ToLower(key)
		if lkey == "match" {
			break // stop at conditional blocks
		}
		if _, seen := cfg[lkey]; !seen {
			cfg[lkey] = val
		}
	}
	return cfg
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

func effective(cfg map[string]string, key, def string) string {
	if v, ok := cfg[strings.ToLower(key)]; ok {
		return strings.ToLower(v)
	}
	return def
}

func auditConfig(cfg map[string]string, path string) []model.Finding {
	var out []model.Finding
	ev := model.WithEvidence("config", path)

	if effective(cfg, "PermitRootLogin", "prohibit-password") == "yes" {
		out = append(out, model.NewFinding("ssh.rootlogin", "SSH permits root login with a password",
			model.SeverityHigh, model.SourceSSH, model.RemediationReview,
			model.WithDescription("Allowing root to log in over SSH with a password makes the most powerful account a direct brute-force target. A single guessed password is a full host compromise."),
			model.WithHowToFix("Set `PermitRootLogin prohibit-password` (key-only) or `no`, and log in as a normal user with sudo instead."),
			ev))
	}

	if effective(cfg, "PermitEmptyPasswords", "no") == "yes" {
		out = append(out, model.NewFinding("ssh.emptypasswords", "SSH allows empty passwords",
			model.SeverityCritical, model.SourceSSH, model.RemediationAuto,
			model.WithDescription("Accounts with no password could be logged into by anyone. This is almost never intended and is trivially exploitable."),
			model.WithHowToFix("Set `PermitEmptyPasswords no` in sshd_config."),
			ev))
	}

	if effective(cfg, "PasswordAuthentication", "yes") == "yes" {
		out = append(out, model.NewFinding("ssh.passwordauth", "SSH allows password authentication",
			model.SeverityMedium, model.SourceSSH, model.RemediationReview,
			model.WithDescription("Password logins are vulnerable to brute-force and credential-stuffing attacks that key-based authentication is immune to. Bots constantly scan the internet for SSH servers accepting passwords."),
			model.WithHowToFix("Set up an SSH key, then set `PasswordAuthentication no`. Make sure your key works before disabling passwords so you do not lock yourself out."),
			ev))
	}

	if tries := atoiDefault(effective(cfg, "MaxAuthTries", "6"), 6); tries > 6 {
		out = append(out, model.NewFinding("ssh.maxauthtries", "SSH allows many authentication attempts per connection",
			model.SeverityLow, model.SourceSSH, model.RemediationAuto,
			model.WithDescription("A high MaxAuthTries lets an attacker try many passwords per connection, speeding up brute-force attacks."),
			model.WithHowToFix("Lower `MaxAuthTries` to 3 or 4."),
			model.WithEvidence("value", strconv.Itoa(tries)), ev))
	}

	if effective(cfg, "X11Forwarding", "no") == "yes" {
		out = append(out, model.NewFinding("ssh.x11forwarding", "SSH X11 forwarding is enabled",
			model.SeverityLow, model.SourceSSH, model.RemediationAuto,
			model.WithDescription("X11 forwarding widens the attack surface and is rarely needed on a headless server."),
			model.WithHowToFix("Set `X11Forwarding no` unless you specifically forward graphical applications."),
			ev))
	}

	return out
}

func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return def
}
