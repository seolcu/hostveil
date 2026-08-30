package fix

import (
	"strings"

	"github.com/seolcu/hostveil/internal/model"
)

// registerProxy wires the proxy-domain fixes into the registry. The first
// one: every other proxy.* finding is deliberately declined (register.go)
// because its remediation is either genuinely ambiguous (Traefik's
// dashboard) or a fact about a config whose syntax and structure varies too
// much per vhost to edit safely (deprecated TLS protocols, directory
// listing). Enabling a single, named, upstream-shipped fail2ban jail has
// neither problem.
func registerProxy(r *Registry) {
	r.Register("proxy.no-scan-jail", buildEnableScanJail)
}

// scanJailPath is a hostveil-owned drop-in, never shared with anything the
// operator or the fail2ban package itself might write — which is what lets
// each action's Transform return a fixed body rather than merge into
// whatever is already there.
const scanJailPath = "/etc/fail2ban/jail.d/hostveil-nginx-scan.conf"

func buildEnableScanJail(f model.Finding) (Fix, error) {
	benefit := "Once fail2ban reloads, an IP that repeatedly requests nonexistent or known-vulnerable paths " +
		"gets banned automatically — no more finding it and banning it yourself."
	warning := "Takes effect on the next `fail2ban-client reload`, not immediately. A shared or NAT'd IP " +
		"address could ban more than the one visitor responsible for it. This only ever affects HTTP(S) " +
		"traffic — never SSH, and never the operator's own access to the host."
	logLines := scanJailLogLines(f)

	return Fix{
		Label: "Enable fail2ban's nginx-botsearch jail",
		Kind:  model.RemediationReview,
		Actions: []Action{
			// Index 0 is what `fix --all --review` applies unattended
			// (Fix's own doc comment) — fail2ban's own upstream default
			// bantime, the safer of the two for something applied without
			// a human looking at it first.
			scanJailAction("Enable it (fail2ban's own default: 10 minute ban)", benefit, warning, logLines, ""),
			scanJailAction("Enable it with a longer ban (1 week)", benefit, warning, logLines, "bantime = 1w\n"),
		},
	}, nil
}

func scanJailAction(label, benefit, warning, logLines, extra string) Action {
	body := "[nginx-botsearch]\nenabled = true\n" + logLines + extra
	return Action{
		Label:           label,
		Benefit:         benefit,
		Warning:         warning,
		Kind:            ActionEdit,
		Path:            scanJailPath,
		CreateIfMissing: true,
		TakesEffectOn:   "`fail2ban-client reload`",
		Transform: func([]byte) ([]byte, error) {
			return []byte(body), nil
		},
	}
}

// scanJailLogLines names the jail's logpath explicitly only when the
// checker found the nginx config pointing somewhere other than the
// compiled-in default. fail2ban's own packaged paths-*.conf already
// resolves nginx-botsearch's default logpath to /var/log/nginx/error.log,
// so writing it out is only necessary on a host that changed that
// directive, not routine — the same reasoning internal/check/sysctl's
// origin-following applies to not re-deriving what a config already gets
// right.
func scanJailLogLines(f model.Finding) string {
	custom := customLogPaths(f.Evidence["error-log"], "/var/log/nginx/error.log")
	if len(custom) == 0 {
		return ""
	}
	return "logpath = " + strings.Join(custom, "\n           ") + "\n"
}

// customLogPaths splits a comma-joined evidence value and reports it only
// when it differs from nginx's single compiled-in default — the common
// case, where nothing needs to be said because fail2ban's own default
// already points at the same place.
func customLogPaths(evidence, compiledDefault string) []string {
	if evidence == "" {
		return nil
	}
	paths := strings.Split(evidence, ",")
	if len(paths) == 1 && paths[0] == compiledDefault {
		return nil
	}
	return paths
}
