package forensic

import (
	"context"
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// journaldCatConfigArgv prints journald's configuration with every drop-in,
// in the order systemd applies them, each file under a "# <path>" header.
// It is asked of systemd rather than reconstructed here, so the precedence
// rules are systemd's own.
var journaldCatConfigArgv = []string{"systemd-analyze", "cat-config", "systemd/journald.conf"}

// JournaldDropInDir is where the fix writes; exported for the fix package.
const JournaldDropInDir = "/etc/systemd/journald.conf.d/"

// journaldConf is the effective [Journal] section, last assignment winning.
type journaldConf struct {
	storage      string // "" when no file sets it: journald's default, auto
	maxRetention string
	dropIns      []string // base names of drop-ins systemd loaded
}

func parseJournaldCatConfig(out string) journaldConf {
	var (
		conf    journaldConf
		section string
	)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "# /") {
			p := strings.TrimPrefix(line, "# ")
			if strings.Contains(p, "journald.conf.d/") {
				conf.dropIns = append(conf.dropIns, path.Base(p))
			}
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.Trim(line, "[]")
			continue
		}
		if section != "Journal" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "Storage":
			conf.storage = strings.ToLower(strings.TrimSpace(v))
		case "MaxRetentionSec":
			conf.maxRetention = strings.TrimSpace(v)
		}
	}
	return conf
}

// journaldDropIn picks a drop-in name that sorts after every one systemd
// already loads, so what the fix writes is what takes effect. Drop-ins are
// applied in filename order whatever directory they are in. Empty means no
// candidate would win.
func journaldDropIn(loaded []string) string {
	last := ""
	for _, b := range loaded {
		if b > last {
			last = b
		}
	}
	for _, name := range []string{"90-hostveil-forensic.conf", "99-hostveil-forensic.conf"} {
		if name > last {
			return JournaldDropInDir + name
		}
	}
	return ""
}

func (c *Checker) checkJournald(ctx context.Context, env platform.Env) ([]model.Finding, bool) {
	if env.ServiceManager != platform.SMSystemd || !platform.Has(env.Runner, "systemd-analyze") {
		// No journald to judge. Syslog-only hosts are covered by logrotate.
		return nil, true
	}
	out, err := env.Runner.Run(ctx, journaldCatConfigArgv[0], journaldCatConfigArgv[1:]...)
	if err != nil {
		return nil, false
	}
	conf := parseJournaldCatConfig(string(out))
	dropIn := journaldDropIn(conf.dropIns)

	var findings []model.Finding
	storage := conf.storage
	if storage == "" {
		storage = "auto"
	}
	volatile := storage == "volatile" || storage == "none" ||
		(storage == "auto" && !c.exists("/var/log/journal"))
	if volatile {
		why := "Storage=" + storage
		if storage == "auto" {
			why += " and /var/log/journal does not exist"
		}
		findings = append(findings, model.NewFinding("forensic.journald-volatile",
			"The system journal is lost at every reboot",
			model.SeverityLow, model.SourceForensic, model.RemediationReview,
			model.WithMetadata("journald_dropin", dropIn),
			model.WithDescription("journald keeps its log in memory only ("+why+"), so every login, service start and error "+
				"recorded before the last reboot is gone. A reboot is also the first thing many people do when a server "+
				"misbehaves — which erases the record of why it misbehaved."),
			model.WithHowToFix("Create "+journaldDropInOrDefault(dropIn)+" containing:\n\n    [Journal]\n    Storage=persistent\n\n"+
				"then run `systemctl restart systemd-journald`. journald creates /var/log/journal itself."),
			model.WithEvidence("Storage", storage),
		))
	}

	if conf.maxRetention != "" {
		d, ok := parseTimespan(conf.maxRetention)
		if ok && d > 0 && d < retentionDays*24*time.Hour {
			findings = append(findings, model.NewFinding("forensic.journald-retention",
				"The system journal deletes entries after less than 90 days",
				model.SeverityLow, model.SourceForensic, model.RemediationReview,
				model.WithMetadata("journald_dropin", dropIn),
				model.WithDescription(fmt.Sprintf("MaxRetentionSec=%s makes journald delete anything older than %s. "+
					"Intrusions are usually noticed weeks after they start, and by then the entries that would show "+
					"how it began are gone.", conf.maxRetention, humanDays(d))),
				model.WithHowToFix("Set `MaxRetentionSec=90day` in "+journaldDropInOrDefault(dropIn)+
					" under [Journal], then run `systemctl restart systemd-journald`. The journal's size cap "+
					"(SystemMaxUse) still applies, so this cannot fill the disk."),
				model.WithEvidence("MaxRetentionSec", conf.maxRetention),
			))
		}
	}
	return findings, true
}

func journaldDropInOrDefault(p string) string {
	if p == "" {
		return "a drop-in under " + JournaldDropInDir + " that sorts after the existing ones"
	}
	return p
}

func humanDays(d time.Duration) string {
	days := int(d.Hours() / 24)
	if days < 1 {
		return d.String()
	}
	return strconv.Itoa(days) + " days"
}

// parseTimespan reads a systemd time span ("2week", "30d", "1month 2d",
// or bare seconds). ok is false for anything it does not understand, which
// callers treat as "no finding" rather than guessing.
func parseTimespan(s string) (time.Duration, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	if n, err := strconv.ParseFloat(s, 64); err == nil {
		return time.Duration(n * float64(time.Second)), true
	}
	units := map[string]time.Duration{
		"s": time.Second, "sec": time.Second, "second": time.Second, "seconds": time.Second,
		"m": time.Minute, "min": time.Minute, "minute": time.Minute, "minutes": time.Minute,
		"h": time.Hour, "hr": time.Hour, "hour": time.Hour, "hours": time.Hour,
		"d": 24 * time.Hour, "day": 24 * time.Hour, "days": 24 * time.Hour,
		"w": 7 * 24 * time.Hour, "week": 7 * 24 * time.Hour, "weeks": 7 * 24 * time.Hour,
		// systemd defines a month as 30.44 days and a year as 365.25.
		"M": 2629800 * time.Second, "month": 2629800 * time.Second, "months": 2629800 * time.Second,
		"y": 31557600 * time.Second, "year": 31557600 * time.Second, "years": 31557600 * time.Second,
	}
	var total time.Duration
	rest := strings.ReplaceAll(s, " ", "")
	for rest != "" {
		i := 0
		for i < len(rest) && (rest[i] >= '0' && rest[i] <= '9' || rest[i] == '.') {
			i++
		}
		if i == 0 {
			return 0, false
		}
		n, err := strconv.ParseFloat(rest[:i], 64)
		if err != nil {
			return 0, false
		}
		rest = rest[i:]
		j := 0
		for j < len(rest) && (rest[j] < '0' || rest[j] > '9') {
			j++
		}
		u, ok := units[rest[:j]]
		if !ok {
			return 0, false
		}
		total += time.Duration(n * float64(u))
		rest = rest[j:]
	}
	return total, true
}
