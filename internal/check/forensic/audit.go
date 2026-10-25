package forensic

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// AuditRulesPath is where the fix writes its rule; exported for the fix
// package, which renders the rule from the finding's uid metadata.
const AuditRulesPath = "/etc/audit/rules.d/90-hostveil-service-exec.rules"

// AuditKey tags the records the fix's rule produces, so `ausearch -k` and
// hostveil triage can find them.
const AuditKey = "hostveil-svc-exec"

var auditdShowArgv = []string{"systemctl", "show", "auditd.service", "--property=LoadState,ActiveState"}

var auditctlListArgv = []string{"auditctl", "-l"}

// webServerUsers are the accounts web servers and PHP-FPM run as on the
// distributions Hostveil supports. A web application served by one of them
// has no reason to start programs, which is what makes recording every
// execve under that uid both cheap and decisive: on a healthy host the log
// stays empty, and a webshell's first command is a record.
var webServerUsers = []string{"www-data", "apache", "nginx", "http"}

// webServerBinaries are what shows a web server is installed at all. Debian
// ships www-data on every host whether or not anything runs as it, so the
// account alone proves nothing.
var webServerBinaries = []string{
	"/usr/sbin/apache2", "/usr/sbin/httpd", "/usr/sbin/nginx",
	"/usr/sbin/php-fpm*", "/usr/sbin/php-fpm[0-9]*",
}

type serviceUser struct{ name, uid string }

func (c *Checker) serviceUsers() []serviceUser {
	installed := false
	for _, pat := range webServerBinaries {
		if m, _ := filepath.Glob(c.path(pat)); len(m) > 0 {
			installed = true
			break
		}
	}
	if !installed {
		return nil
	}
	passwd, ok := c.read("/etc/passwd")
	if !ok {
		return nil
	}
	var out []serviceUser
	for _, line := range strings.Split(passwd, "\n") {
		f := strings.Split(line, ":")
		if len(f) < 3 {
			continue
		}
		for _, n := range webServerUsers {
			if f[0] == n {
				out = append(out, serviceUser{name: f[0], uid: f[2]})
			}
		}
	}
	return out
}

// execRuleFor reports whether an auditctl -l listing records execve for
// the given user, by uid or by name, as auid, uid or euid.
func execRuleFor(listing string, u serviceUser) bool {
	who := regexp.MustCompile(`-F (?:e|a)?uid=(?:` + regexp.QuoteMeta(u.uid) + `|` + regexp.QuoteMeta(u.name) + `)(?:\s|$)`)
	for _, line := range strings.Split(listing, "\n") {
		if strings.Contains(line, "execve") && who.MatchString(line) {
			return true
		}
	}
	return false
}

func (c *Checker) checkAudit(ctx context.Context, env platform.Env) ([]model.Finding, bool) {
	if env.ServiceManager != platform.SMSystemd {
		return nil, true
	}
	out, err := env.Runner.Run(ctx, auditdShowArgv[0], auditdShowArgv[1:]...)
	if err != nil {
		return nil, false
	}
	load := platform.ShowProperty(string(out), "LoadState")
	active := platform.ShowProperty(string(out), "ActiveState")
	if load != "loaded" || active != "active" {
		state := "not installed"
		if load == "loaded" {
			state = "installed but " + active
		}
		return []model.Finding{model.NewFinding("forensic.auditd-missing",
			"Nothing records which programs run on this host",
			model.SeverityLow, model.SourceForensic, model.RemediationManual,
			model.WithDescription("The Linux audit daemon is "+state+", so the kernel's record of who ran what is "+
				"not kept anywhere. When a web application is exploited, the attacker's first commands run as the "+
				"web server's account — and without auditing, the only trace of them is whatever they chose not to delete."),
			model.WithHowToFix("Install and start auditd (`apt-get install auditd` or `dnf install audit`, then "+
				"`systemctl enable --now auditd`) and run Hostveil again: it will offer the rules that record what "+
				"your web server's account executes."),
			model.WithEvidence("auditd", state),
		)}, true
	}

	users := c.serviceUsers()
	if len(users) == 0 {
		return nil, true
	}
	listing, err := env.Runner.Run(ctx, auditctlListArgv[0], auditctlListArgv[1:]...)
	if err != nil {
		// auditctl needs root; a non-root scan cannot see the rules.
		return nil, false
	}
	var findings []model.Finding
	for _, u := range users {
		if execRuleFor(string(listing), u) {
			continue
		}
		findings = append(findings, model.NewFinding("forensic.service-exec-unaudited",
			"Programs started by the web server's account are not recorded",
			model.SeverityLow, model.SourceForensic, model.RemediationReview,
			model.WithService(u.name),
			model.WithMetadata("service_uid", u.uid),
			model.WithDescription(fmt.Sprintf("A web server is installed and runs as %s (uid %s), and no audit rule "+
				"records the programs that account starts. A web application almost never starts programs, so on a "+
				"healthy host such a rule records nothing; after a remote-code-execution bug it records the attacker's "+
				"first command, with its time and arguments.", u.name, u.uid)),
			model.WithHowToFix(fmt.Sprintf("Create %s containing:\n\n    -a always,exit -F arch=b64 -S execve -F euid=%s -k %s\n"+
				"    -a always,exit -F arch=b32 -S execve -F euid=%s -k %s\n\nthen run `augenrules --load`. "+
				"Review the records with `ausearch -k %s -i`.", AuditRulesPath, u.uid, AuditKey, u.uid, AuditKey, AuditKey)),
			model.WithEvidence("account", u.name+" (uid "+u.uid+")"),
		))
	}
	return findings, true
}
