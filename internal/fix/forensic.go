package fix

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/seolcu/hostveil/internal/model"
)

// registerForensic registers the forensic-readiness fixes. Each one makes
// the host keep evidence it was throwing away; none of them changes what any
// service can do, which is why the only thing they share with the hardening
// fixes is the checkpoint.
//
// They are all Review. Writing the file is reversible, but each has a cost
// only the operator can weigh: a persistent journal and longer rotation use
// disk, and an audit rule on a web application that does start programs —
// an image converter shelling out, a cron-style PHP job — fills the audit log.
func registerForensic(r *Registry) {
	r.Register("forensic.journald-volatile", buildJournaldPersistent)
	r.Register("forensic.journald-retention", buildJournaldRetention)
	r.Register("forensic.service-exec-unaudited", buildServiceExecAudit)
	r.Register("forensic.logrotate-short", buildLogrotateLonger)
}

var journaldRestart = [][]string{{"systemctl", "restart", "systemd-journald"}}

func journaldDropInFix(f model.Finding, key, value, label, benefit, warning string) (Fix, error) {
	p := f.Metadata["journald_dropin"]
	if p == "" {
		return Fix{}, fmt.Errorf("no drop-in name under /etc/systemd/journald.conf.d/ would sort after the ones "+
			"journald already loads, so a file written for %s would be overridden", f.ID)
	}
	return Fix{
		FindingID: f.ID,
		Label:     label,
		Kind:      model.RemediationReview,
		Actions: []Action{{
			Label:           "Set " + key + "=" + value + " in " + p + " and restart journald",
			Benefit:         benefit,
			Warning:         warning + " The drop-in is a new file with a checkpoint; rolling it back deletes it and restarts journald.",
			Kind:            ActionEdit,
			Path:            p,
			CreateIfMissing: true,
			Transform:       setINIKey("Journal", key, value),
			AfterWrite:      journaldRestart,
		}},
	}, nil
}

func buildJournaldPersistent(f model.Finding) (Fix, error) {
	return journaldDropInFix(f, "Storage", "persistent",
		"Keep the system journal across reboots",
		"Logins, service starts and errors survive a reboot, so the record of what happened before one is still "+
			"there when someone looks.",
		"The journal now uses disk under /var/log/journal, capped by journald at 10% of the filesystem (4GB at most) "+
			"unless SystemMaxUse says otherwise.")
}

func buildJournaldRetention(f model.Finding) (Fix, error) {
	return journaldDropInFix(f, "MaxRetentionSec", "90day",
		"Keep journal entries for 90 days",
		"Entries from the last three months stay available, which covers the weeks most intrusions go unnoticed.",
		"The journal keeps more history and uses more disk, still within its SystemMaxUse cap.")
}

// setINIKey sets key=value in [section] of a systemd-style INI file,
// replacing an existing assignment in that section or appending one.
func setINIKey(section, key, value string) func([]byte) ([]byte, error) {
	line := key + "=" + value
	return func(in []byte) ([]byte, error) {
		lines := strings.Split(strings.TrimRight(string(in), "\n"), "\n")
		if len(strings.TrimSpace(string(in))) == 0 {
			return []byte("[" + section + "]\n" + line + "\n"), nil
		}
		cur, last := "", -1
		for i, l := range lines {
			t := strings.TrimSpace(l)
			if strings.HasPrefix(t, "[") {
				cur = strings.Trim(t, "[]")
				continue
			}
			if cur != section {
				continue
			}
			last = i
			if k, _, ok := strings.Cut(t, "="); ok && strings.TrimSpace(k) == key {
				lines[i] = line
				return []byte(strings.Join(lines, "\n") + "\n"), nil
			}
		}
		if last < 0 {
			for i, l := range lines {
				if strings.TrimSpace(l) == "["+section+"]" {
					last = i
				}
			}
		}
		if last < 0 {
			return []byte(strings.Join(lines, "\n") + "\n\n[" + section + "]\n" + line + "\n"), nil
		}
		out := append([]string{}, lines[:last+1]...)
		out = append(out, line)
		out = append(out, lines[last+1:]...)
		return []byte(strings.Join(out, "\n") + "\n"), nil
	}
}

// These match internal/check/forensic, which names the same file and key in
// its how-to-fix text, and the key is what hostveil triage searches for.
const (
	auditRulesPath = "/etc/audit/rules.d/90-hostveil-service-exec.rules"
	auditKey       = "hostveil-svc-exec"
)

var augenrulesLoad = [][]string{{"augenrules", "--load"}}

func buildServiceExecAudit(f model.Finding) (Fix, error) {
	uid := f.Metadata["service_uid"]
	if _, err := strconv.Atoi(uid); err != nil {
		return Fix{}, fmt.Errorf("finding %s carries no numeric uid", f.ID)
	}
	rules := []string{
		"-a always,exit -F arch=b64 -S execve -F euid=" + uid + " -k " + auditKey,
		"-a always,exit -F arch=b32 -S execve -F euid=" + uid + " -k " + auditKey,
	}
	return Fix{
		FindingID: f.ID,
		Label:     "Record programs started by " + f.Service,
		Kind:      model.RemediationReview,
		Actions: []Action{{
			Label: "Write an execve rule for uid " + uid + " to " + auditRulesPath + " and load it",
			Benefit: "Every program the web server's account starts is recorded with its time and arguments, so a " +
				"webshell's first command is evidence rather than a guess.",
			Warning: "A web application that legitimately starts programs — an image converter, a PDF renderer, a " +
				"git-backed wiki — writes an audit record each time it does; watch `ausearch -k " + auditKey +
				"` for a day after applying. The rule file is a checkpoint; rolling it back removes the rule and reloads.",
			Kind:            ActionEdit,
			Path:            auditRulesPath,
			CreateIfMissing: true,
			Transform: func(in []byte) ([]byte, error) {
				out := string(in)
				if out == "" {
					out = "# Written by Hostveil: record programs started by web-server accounts.\n"
				}
				if !strings.HasSuffix(out, "\n") {
					out += "\n"
				}
				for _, r := range rules {
					if !strings.Contains(out, r) {
						out += r + "\n"
					}
				}
				return []byte(out), nil
			},
			AfterWrite:   augenrulesLoad,
			AfterRestore: augenrulesLoad,
		}},
	}, nil
}

// logrotate rewriting. This mirrors the checker's reading of the file —
// blocks, the rotate count, the period, size-only rotation — and only ever
// raises a rotate count, so it cannot shorten anything.

var lrPeriodDays = map[string]int{"daily": 1, "weekly": 7, "monthly": 30, "yearly": 365}

const lrTargetDays = 90

func lrRotateFor(period string) int {
	d := lrPeriodDays[period]
	return (lrTargetDays+d-1)/d - 1
}

var lrRotate = regexp.MustCompile(`^(\s*)rotate\s+(\d+)\s*$`)

func raiseLogrotate(defPeriod string) func([]byte) ([]byte, error) {
	return func(in []byte) ([]byte, error) {
		lines := strings.Split(string(in), "\n")
		var (
			inBlock, script, sized bool
			period                 string
			rotIdx, open           int
			changed                bool
		)
		var inserts []struct {
			at   int
			line string
		}
		for i, l := range lines {
			t := strings.TrimSpace(l)
			if script {
				if t == "endscript" {
					script = false
				}
				continue
			}
			if !inBlock {
				if strings.Contains(t, "{") && !strings.HasPrefix(t, "#") {
					inBlock, sized, period, rotIdx, open = true, false, "", -1, i
				}
				continue
			}
			f := strings.Fields(t)
			if len(f) == 0 || strings.HasPrefix(t, "#") {
				continue
			}
			switch {
			case t == "}":
				inBlock = false
				per := period
				if per == "" {
					if sized {
						continue
					}
					per = defPeriod
				}
				if _, ok := lrPeriodDays[per]; !ok {
					continue
				}
				want := lrRotateFor(per)
				if rotIdx >= 0 {
					m := lrRotate.FindStringSubmatch(lines[rotIdx])
					if n, _ := strconv.Atoi(m[2]); n < want {
						lines[rotIdx] = m[1] + "rotate " + strconv.Itoa(want)
						changed = true
					}
				} else {
					inserts = append(inserts, struct {
						at   int
						line string
					}{open + 1, "\trotate " + strconv.Itoa(want)})
					changed = true
				}
			case f[0] == "postrotate" || f[0] == "prerotate" || f[0] == "firstaction" || f[0] == "lastaction" || f[0] == "preremove":
				script = true
			case lrRotate.MatchString(l):
				rotIdx = i
			case f[0] == "size":
				sized = true
			default:
				if _, ok := lrPeriodDays[f[0]]; ok && len(f) == 1 {
					period = f[0]
				}
			}
		}
		if !changed {
			return in, nil
		}
		for k := len(inserts) - 1; k >= 0; k-- {
			at := inserts[k].at
			lines = append(lines[:at], append([]string{inserts[k].line}, lines[at:]...)...)
		}
		return []byte(strings.Join(lines, "\n")), nil
	}
}

func buildLogrotateLonger(f model.Finding) (Fix, error) {
	p := f.Metadata["logrotate_file"]
	if p == "" {
		return Fix{}, fmt.Errorf("finding %s names no logrotate file", f.ID)
	}
	per := f.Metadata["default_period"]
	if per == "" {
		per = "weekly"
	}
	return Fix{
		FindingID: f.ID,
		Label:     "Keep the logs in " + p + " for 90 days",
		Kind:      model.RemediationReview,
		Actions: []Action{{
			Label:   "Raise the rotate count in " + p + " to cover 90 days",
			Benefit: "Authentication and web access logs reach back three months, which covers the weeks most intrusions go unnoticed.",
			Warning: "Rotated logs are compressed, but a busy web server's three months can still be gigabytes. The file " +
				"belongs to a package, so its next upgrade asks whether to keep your version. The edit is a checkpoint and rolls back.",
			Kind:      ActionEdit,
			Path:      p,
			Transform: raiseLogrotate(per),
		}},
	}, nil
}
