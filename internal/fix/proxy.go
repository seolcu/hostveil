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

// scanJailLogLines always states an explicit backend and logpath, never
// conditionally.
//
// Verified against a real fail2ban process, not assumed from its docs:
// fail2ban's "auto" backend prefers the systemd journal over a jail's own
// logpath whenever the filter defines a journalmatch, which nginx-botsearch
// does — and nginx does not write request-level entries to the journal, so
// a bare `enabled = true` with nothing else silently watches nothing at
// all. "Currently failed: 0" against real repeated-404 traffic, even with
// logpath itself restated to the exact value fail2ban's own default already
// resolves to — only adding an explicit `backend = auto` switched it onto
// the log files, at which point a scripted probe past maxretry produced a
// real ban within seconds. logpath names both files, not just one: the
// filter matches an access-log-style 404 line as well as an error-log-style
// failed-open line, and which one a given host actually populates depends
// on whether the request reaches a static-file lookup at all — a bare vhost
// returning its own 404 never does, so only the access log carries it.
//
// The path itself still prefers the checker's own evidence over a literal
// default, and falls back to fail2ban's %(nginx_access_log)s/
// %(nginx_error_log)s macros rather than a hardcoded path when there is no
// evidence — those macros are what stay portable across a distribution
// hostveil has not specifically checked, the same reasoning
// internal/check/sysctl's origin-following applies to not re-deriving what
// a config already gets right.
func scanJailLogLines(f model.Finding) string {
	access := firstLogPath(f.Evidence["access-log"], "%(nginx_access_log)s")
	errLog := firstLogPath(f.Evidence["error-log"], "%(nginx_error_log)s")
	return "backend = auto\n" +
		"logpath = " + access + "\n" +
		"          " + errLog + "\n"
}

// firstLogPath takes the first of a comma-joined evidence value, or a
// fallback when the checker recorded none. Evidence beyond the first path
// is informational for a reader of the finding; fail2ban's own logpath
// override here is a courtesy default, not an attempt to enumerate every
// log target an unusual config might have.
func firstLogPath(evidence, fallback string) string {
	if evidence == "" {
		return fallback
	}
	if i := strings.IndexByte(evidence, ','); i >= 0 {
		return evidence[:i]
	}
	return evidence
}
