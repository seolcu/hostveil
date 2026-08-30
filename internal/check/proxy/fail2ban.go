package proxy

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

const defaultFail2banConfDir = "/etc/fail2ban"

func (c *Checker) fail2banDir() string {
	if c.Fail2banConfDir != "" {
		return c.Fail2banConfDir
	}
	return defaultFail2banConfDir
}

// auditScanProtection reports whether fail2ban is installed but not
// configured to watch this proxy for URL/path scanning. It only runs once
// nginx itself has been found — the caller calls it from inside the same
// block that already runs auditNginx — because there is nothing for it to
// say about a host with no nginx config to protect.
//
// "Could not tell whether fail2ban is installed" degrades the domain's
// coverage rather than passing silently, the same discipline the nginx
// directive walk right above it already holds to. "fail2ban is not
// installed" is a real answer (systemd loaded no such unit), not a gap:
// updates.fail2ban already reports that case, so this stays silent instead
// of duplicating it.
func (c *Checker) auditScanProtection(ctx context.Context, r platform.CommandRunner, cov *check.Coverage) []model.Finding {
	installed, ok := fail2banInstalled(ctx, r)
	if !ok {
		cov.Missed(0, "cannot tell whether fail2ban is installed — systemctl did not answer")
		return nil
	}
	if !installed {
		return nil
	}

	enabled, unread := c.nginxJailEnabled()
	if len(unread) > 0 {
		cov.Missed(0, "could not read "+strings.Join(unread, ", ")+
			" — fail2ban's jail configuration was not audited; re-run with sudo")
		return nil
	}
	if enabled {
		return nil
	}

	accessLog, errorLog := nginxLogDirectives(c.root())
	return []model.Finding{scanProtectionFinding(accessLog, errorLog)}
}

// fail2banInstalled reports whether fail2ban.service exists as a systemd
// unit, and whether the question could be answered at all.
//
// LoadState rather than is-active or fail2ban-client: an installed-but-not-
// running service is still something the fix this finding offers can act
// on, and asking systemd whether the unit was loaded is the same idiom
// internal/check/updates uses for dnf-automatic.timer — a unit systemd has
// never heard of answers with no error and an empty property, which is a
// real "not installed" rather than a probe that failed.
func fail2banInstalled(ctx context.Context, r platform.CommandRunner) (installed, ok bool) {
	out, err := r.Run(ctx, "systemctl", "show", "fail2ban.service", "--property=LoadState")
	if err != nil {
		return false, false
	}
	return strings.Contains(string(out), "LoadState=loaded"), true
}

// nginxJailEnabled reads fail2ban's jail.local (if present) and every
// jail.d/*.conf, looking for a [nginx-botsearch] section with enabled set
// to a true-like value.
//
// This is a section/key scan in the same spirit as statements() below —
// not a real INI parser, because fail2ban's %(...)s interpolation and
// [DEFAULT] inheritance would make a faithful parse a much bigger job than
// deciding "does hostveil's own drop-in, or one the operator already wrote,
// turn this on" needs. It returns the files it could not read rather than
// treating them as absent: jail.d commonly holds files an unprivileged scan
// cannot open, and reading that as "no jail configured" is exactly the
// mistake this checker's own nginx-config walk already refuses to make.
func (c *Checker) nginxJailEnabled() (enabled bool, unread []string) {
	dir := c.fail2banDir()

	var files []string
	if fi, err := os.Stat(filepath.Join(dir, "jail.local")); err == nil && !fi.IsDir() {
		files = append(files, filepath.Join(dir, "jail.local"))
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "jail.d", "*.conf"))
	files = append(files, matches...)
	sort.Strings(files)

	for _, f := range files {
		b, err := platform.ReadFileBounded(f, 1<<20)
		if err != nil {
			unread = append(unread, f)
			continue
		}
		if jailEnabledIn(string(b), "nginx-botsearch") {
			enabled = true
		}
	}
	return enabled, unread
}

// jailEnabledIn reports whether section carries "enabled = <true-like>"
// before the next section header or EOF.
func jailEnabledIn(body, section string) bool {
	inSection := false
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if i := strings.IndexAny(trimmed, ";#"); i >= 0 {
			trimmed = strings.TrimSpace(trimmed[:i])
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			inSection = trimmed == "["+section+"]"
			continue
		}
		if !inSection {
			continue
		}
		key, val, ok := strings.Cut(trimmed, "=")
		if !ok || strings.TrimSpace(key) != "enabled" {
			continue
		}
		if isTrue(strings.TrimSpace(val)) {
			return true
		}
	}
	return false
}

// nginxLogDirectives collects every access_log/error_log directive's target
// path from the nginx configuration, skipping "off" and syslog targets.
// Used only to decide whether the fix needs an explicit logpath override —
// fail2ban's own packaged paths-*.conf already resolves its jails' default
// logpath to the compiled-in location, so this only has something to say on
// a host that changed it.
func nginxLogDirectives(root string) (access, errorLog []string) {
	files, _ := nginxFiles(root)
	seenA, seenE := map[string]bool{}, map[string]bool{}
	for _, f := range files {
		b, err := platform.ReadFileBounded(f, 4<<20)
		if err != nil {
			continue
		}
		for _, st := range statements(string(b)) {
			if len(st) < 2 {
				continue
			}
			switch st[0] {
			case "access_log":
				if p := logTarget(st[1]); p != "" && !seenA[p] {
					seenA[p] = true
					access = append(access, p)
				}
			case "error_log":
				if p := logTarget(st[1]); p != "" && !seenE[p] {
					seenE[p] = true
					errorLog = append(errorLog, p)
				}
			}
		}
	}
	sort.Strings(access)
	sort.Strings(errorLog)
	return access, errorLog
}

func logTarget(v string) string {
	if v == "off" || strings.HasPrefix(v, "syslog:") {
		return ""
	}
	return v
}

func scanProtectionFinding(accessLog, errorLog []string) model.Finding {
	opts := []model.FindingOption{
		model.WithDescription(
			"fail2ban is installed, but its nginx-botsearch jail is not enabled. That jail is built specifically " +
				"to catch repeated requests for nonexistent or known-vulnerable paths — /wp-login.php, /.env, " +
				"/phpmyadmin, and the rest of the pattern behind most automated reconnaissance — and ban the " +
				"source. Right now nginx answers that traffic with its own 404 and nothing else happens."),
		model.WithHowToFix(
			"Enable it: write a drop-in under /etc/fail2ban/jail.d/ setting `enabled = true` for " +
				"[nginx-botsearch], then `fail2ban-client reload`."),
	}
	if len(accessLog) > 0 {
		opts = append(opts, model.WithEvidence("access-log", strings.Join(accessLog, ",")))
	}
	if len(errorLog) > 0 {
		opts = append(opts, model.WithEvidence("error-log", strings.Join(errorLog, ",")))
	}
	return model.NewFinding("proxy.no-scan-jail",
		"Nothing is watching this proxy for URL/path scanning",
		model.SeverityMedium, model.SourceProxy, model.RemediationReview, opts...)
}
