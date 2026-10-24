package forensic

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

var timedatectlArgv = []string{"timedatectl", "show", "--property=NTPSynchronized,NTP"}

// checkTimeSync reports a clock nobody keeps right. Every timeline an
// investigation builds lines up this host's log times against each other and
// against the outside world — a provider's abuse report, another server's
// log — and a drifting clock makes "the login came before the upload" a
// guess.
func (c *Checker) checkTimeSync(ctx context.Context, env platform.Env) ([]model.Finding, bool) {
	if env.ServiceManager != platform.SMSystemd || !platform.Has(env.Runner, "timedatectl") {
		return nil, true
	}
	out, err := env.Runner.Run(ctx, timedatectlArgv[0], timedatectlArgv[1:]...)
	if err != nil {
		return nil, false
	}
	synced := platform.ShowProperty(string(out), "NTPSynchronized")
	if synced != "no" {
		return nil, true
	}
	ntp := platform.ShowProperty(string(out), "NTP")
	return []model.Finding{model.NewFinding("forensic.time-unsynced",
		"The system clock is not synchronised",
		model.SeverityLow, model.SourceForensic, model.RemediationManual,
		model.WithDescription("The clock has not been synchronised with a time server (NTP="+ntp+"), so the times in "+
			"every log on this host may be off by an unknown amount. Putting events in order — and matching them "+
			"against anyone else's logs — depends on those times."),
		model.WithHowToFix("Run `timedatectl set-ntp true`, or configure chrony or systemd-timesyncd with a time "+
			"server you trust, and confirm with `timedatectl` that \"System clock synchronized\" reads yes."),
		model.WithEvidence("NTPSynchronized", synced),
		model.WithEvidence("NTP", ntp),
	)}, true
}

// LogrotateFiles are the rotation configs that decide how long the logs an
// investigation reads first — authentication and web access — are kept.
var LogrotateFiles = []string{
	"/etc/logrotate.d/rsyslog",
	"/etc/logrotate.d/apache2",
	"/etc/logrotate.d/httpd",
	"/etc/logrotate.d/nginx",
}

// periodDays is how many days one rotation period covers.
var periodDays = map[string]int{"daily": 1, "weekly": 7, "monthly": 30, "yearly": 365}

// LogrotateBlock is one `{ … }` stanza: which files it rotates, how often,
// and how many old copies it keeps.
type LogrotateBlock struct {
	Paths  []string
	Rotate int // -1 when the block does not set it
	Period string
	// Sized is true when the block rotates by size only, which makes its
	// coverage depend on traffic and not on anything written here.
	Sized bool
}

// Days is how far back the block's logs reach, or -1 when that depends on
// something this file does not say.
func (b LogrotateBlock) Days(defRotate int, defPeriod string) int {
	rot, per := b.Rotate, b.Period
	if rot < 0 {
		rot = defRotate
	}
	if per == "" {
		if b.Sized {
			return -1
		}
		per = defPeriod
	}
	d, ok := periodDays[per]
	if !ok || rot < 0 {
		return -1
	}
	return (rot + 1) * d // the live file plus every rotated copy
}

var rotateLine = regexp.MustCompile(`^\s*rotate\s+(\d+)\s*$`)

// ParseLogrotate splits a logrotate file into its blocks. It reads only the
// directives that decide coverage and ignores scripts.
func ParseLogrotate(src string) []LogrotateBlock {
	var (
		blocks  []LogrotateBlock
		pending []string
		cur     *LogrotateBlock
		script  bool
	)
	for _, line := range strings.Split(src, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if script {
			if t == "endscript" {
				script = false
			}
			continue
		}
		if cur == nil {
			before, _, open := strings.Cut(t, "{")
			pending = append(pending, strings.Fields(before)...)
			if open {
				cur = &LogrotateBlock{Paths: pending, Rotate: -1}
				pending = nil
			}
			continue
		}
		if t == "}" {
			blocks = append(blocks, *cur)
			cur = nil
			continue
		}
		f := strings.Fields(t)
		switch f[0] {
		case "postrotate", "prerotate", "firstaction", "lastaction", "preremove":
			script = true
		case "rotate":
			if len(f) > 1 {
				if n, err := strconv.Atoi(f[1]); err == nil {
					cur.Rotate = n
				}
			}
		case "daily", "weekly", "monthly", "yearly":
			cur.Period = f[0]
		case "size":
			cur.Sized = true
		}
	}
	return blocks
}

// logrotateDefaults reads the global rotate count and period from
// /etc/logrotate.conf, falling back to logrotate's own defaults (keep none,
// rotate weekly on Debian's shipped config).
func (c *Checker) logrotateDefaults() (int, string) {
	rot, per := 0, "weekly"
	src, ok := c.read("/etc/logrotate.conf")
	if !ok {
		return rot, per
	}
	depth := 0
	for _, line := range strings.Split(src, "\n") {
		t := strings.TrimSpace(line)
		depth += strings.Count(t, "{") - strings.Count(t, "}")
		if depth > 0 || strings.HasPrefix(t, "#") {
			continue
		}
		if m := rotateLine.FindStringSubmatch(t); m != nil {
			rot, _ = strconv.Atoi(m[1])
		}
		if _, ok := periodDays[t]; ok {
			per = t
		}
	}
	return rot, per
}

// RotateFor is the rotate count that makes one period reach the retention
// target, given the live file counts as one period.
func RotateFor(period string) int {
	d := periodDays[period]
	if d == 0 {
		return 0
	}
	return (retentionDays+d-1)/d - 1
}

func (c *Checker) checkLogrotate() ([]model.Finding, bool) {
	defRot, defPer := c.logrotateDefaults()
	var findings []model.Finding
	for _, p := range LogrotateFiles {
		src, ok := c.read(p)
		if !ok {
			continue
		}
		shortest, paths := -1, []string(nil)
		for _, b := range ParseLogrotate(src) {
			d := b.Days(defRot, defPer)
			if d < 0 || d >= retentionDays {
				continue
			}
			if shortest < 0 || d < shortest {
				shortest = d
			}
			paths = append(paths, b.Paths...)
		}
		if shortest < 0 {
			continue
		}
		sort.Strings(paths)
		findings = append(findings, model.NewFinding("forensic.logrotate-short",
			"Logs are deleted after "+strconv.Itoa(shortest)+" days",
			model.SeverityLow, model.SourceForensic, model.RemediationReview,
			model.WithService(p),
			model.WithMetadata("logrotate_file", p),
			model.WithMetadata("default_period", defPer),
			model.WithDescription(fmt.Sprintf("%s keeps %s for about %d days before deleting them. Most intrusions "+
				"are noticed weeks after they began; by then the authentication and access records that would show "+
				"how they began have been rotated away.", p, strings.Join(paths, ", "), shortest)),
			model.WithHowToFix(fmt.Sprintf("Raise `rotate` in %s so each block keeps at least %d days "+
				"(for example `rotate %d` with `weekly`, `rotate %d` with `daily`). Rotated logs are compressed, "+
				"so the extra history costs little disk.", p, retentionDays, RotateFor("weekly"), RotateFor("daily"))),
			model.WithEvidence("kept for", strconv.Itoa(shortest)+" days"),
		))
	}
	return findings, true
}

// apacheConfGlobs and nginxConfGlobs are where each server's log directives
// live on Debian- and Red Hat-family hosts.
var apacheConfGlobs = []string{
	"/etc/apache2/apache2.conf", "/etc/apache2/sites-enabled/*", "/etc/apache2/conf-enabled/*",
	"/etc/httpd/conf/httpd.conf", "/etc/httpd/conf.d/*.conf",
}

var nginxConfGlobs = []string{
	"/etc/nginx/nginx.conf", "/etc/nginx/conf.d/*.conf", "/etc/nginx/sites-enabled/*",
}

var (
	apacheLogFormat = regexp.MustCompile(`(?mi)^\s*LogFormat\s+"((?:[^"\\]|\\.)*)"\s+(\S+)`)
	apacheCustomLog = regexp.MustCompile(`(?mi)^\s*CustomLog\s+(\S+)\s+(?:"((?:[^"\\]|\\.)*)"|(\S+))`)
	nginxLogFormat  = regexp.MustCompile(`(?s)log_format\s+(\S+)\s+(?:escape=\S+\s+)?((?:'[^']*'\s*|"[^"]*"\s*)+);`)
	nginxAccessLog  = regexp.MustCompile(`(?m)^\s*access_log\s+([^;\s]+)(?:\s+([^;\s]+))?[^;]*;`)
)

func (c *Checker) readGlobs(globs []string) (string, bool) {
	var b strings.Builder
	found := false
	for _, g := range globs {
		m, _ := filepath.Glob(c.path(g))
		for _, p := range m {
			if s, ok := c.read(strings.TrimPrefix(p, filepath.Clean(c.Root))); ok {
				b.WriteString(s + "\n")
				found = true
			}
		}
	}
	return b.String(), found
}

// checkWebLogs reports an access log that does not record how big each
// request was. An exploit that smuggles a payload in a request body looks
// in a standard "combined" log like any other POST to the same URL; the
// request's size is often the only thing in the log that tells them apart.
func (c *Checker) checkWebLogs() ([]model.Finding, bool) {
	var findings []model.Finding
	if conf, ok := c.readGlobs(apacheConfGlobs); ok {
		formats := map[string]string{}
		for _, m := range apacheLogFormat.FindAllStringSubmatch(conf, -1) {
			formats[m[2]] = m[1]
		}
		var missing []string
		for _, m := range apacheCustomLog.FindAllStringSubmatch(conf, -1) {
			format := m[2]
			if format == "" {
				format = formats[m[3]]
			}
			if !strings.Contains(format, "%I") {
				missing = append(missing, m[1])
			}
		}
		if len(missing) > 0 {
			findings = append(findings, webLogFinding("apache", missing,
				"add `%I` (bytes received, from mod_logio) and `%D` (time taken) to the LogFormat your CustomLog uses — "+
					"for example a copy of `combined` named `forensic` with ` %I %D` appended — and switch the CustomLog to it"))
		}
	}
	if conf, ok := c.readGlobs(nginxConfGlobs); ok {
		formats := map[string]string{"combined": ""}
		for _, m := range nginxLogFormat.FindAllStringSubmatch(conf, -1) {
			formats[m[1]] = m[2]
		}
		var missing []string
		logs := nginxAccessLog.FindAllStringSubmatch(conf, -1)
		for _, m := range logs {
			if m[1] == "off" {
				continue
			}
			name := m[2]
			if name == "" || strings.Contains(name, "=") {
				name = "combined"
			}
			if !strings.Contains(formats[name], "$request_length") {
				missing = append(missing, m[1])
			}
		}
		if len(logs) == 0 {
			missing = append(missing, "the default access log")
		}
		if len(missing) > 0 {
			findings = append(findings, webLogFinding("nginx", missing,
				"define a `log_format` that adds `$request_length` and `$request_time` to the combined fields and name it in each `access_log`"))
		}
	}
	return findings, true
}

func webLogFinding(server string, logs []string, how string) model.Finding {
	return model.NewFinding("forensic.weblog-no-size",
		"The web access log does not record request sizes",
		model.SeverityLow, model.SourceForensic, model.RemediationManual,
		model.WithService(server),
		model.WithDescription("The "+server+" access log ("+strings.Join(logs, ", ")+") records each request's URL and "+
			"status but not how large it was. An exploit carried in a request body looks, in that log, exactly like "+
			"the ordinary requests to the same page around it, so after a vulnerability is announced there is no way "+
			"to tell from the log whether this host was hit."),
		model.WithHowToFix("To record it, "+how+", then reload "+server+"."),
		model.WithEvidence("server", server),
	)
}

var rsyslogForward = regexp.MustCompile(`(?m)^[^#\n]*(?:\s@@?[\[\w]|omfwd)`)

var journalUploadArgv = []string{"systemctl", "show", "systemd-journal-upload.service", "--property=ActiveState"}

// checkRemoteLog reports that no log leaves the host. Whoever gains root on a
// server can delete its logs, and the first thing a careful intruder does is
// exactly that; a copy elsewhere is the only one they cannot reach.
func (c *Checker) checkRemoteLog(ctx context.Context, env platform.Env) ([]model.Finding, bool) {
	if conf, ok := c.readGlobs([]string{"/etc/rsyslog.conf", "/etc/rsyslog.d/*.conf"}); ok && rsyslogForward.MatchString(conf) {
		return nil, true
	}
	if env.ServiceManager == platform.SMSystemd {
		if out, err := env.Runner.Run(ctx, journalUploadArgv[0], journalUploadArgv[1:]...); err == nil &&
			platform.ShowProperty(string(out), "ActiveState") == "active" {
			return nil, true
		}
	}
	return []model.Finding{model.NewFinding("forensic.no-remote-log",
		"Every log is kept only on this host",
		model.SeverityLow, model.SourceForensic, model.RemediationManual,
		model.WithDescription("Neither rsyslog nor systemd-journal-upload sends logs anywhere else. Anyone who gains "+
			"root here can edit or delete every record of how they did it, and an intruder who knows what they are "+
			"doing will."),
		model.WithHowToFix("Forward at least the authentication log to another machine you control — an rsyslog "+
			"`*.* @@logs.example:514` line, or systemd-journal-upload to a systemd-journal-remote host."),
	)}, true
}
