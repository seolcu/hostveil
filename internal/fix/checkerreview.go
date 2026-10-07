package fix

import (
	"strings"

	"github.com/seolcu/hostveil/internal/model"
)

// checkerDeclaresReview lists the fixes whose shape is Auto's — one
// mechanical edit — while the checker that reports the finding always asks
// for a person, and why.
//
// Engine.classify settles a finding's remediation as the more cautious of the
// checker's declaration and the fix's kind, so a fix registered Auto here was
// always shown as Review. The registry saying so too is what lets everything
// that reads the registry without a live host — the docs' Fix column, the
// published counts, cmd/sitegen — read the kind a user is shown, instead of
// keeping a copy of this list beside each of them. It used to be two such
// copies, in cmd/sitegen's and internal/docs' tests, and every new fix meant
// editing both.
//
// Only checkers that declare Review unconditionally belong here. One whose
// declaration depends on the finding — agent.exec-unrestricted is Review when
// tools.exec.security tripped and Auto when only tools.exec.ask did — must not
// be floored, because that would turn the Auto case Review too.
var checkerDeclaresReview = map[string]string{
	"ssh.passwordauth":               "disabling passwords locks out anyone whose key is not already working",
	"ssh.gatewayports":               "a published tunnel may be the only route to a service, including the operator's",
	"ssh.hostbasedauth":              "the trusting host may be how the operator gets in",
	"ssh.kbdinteractive":             "PAM one-time codes run through the same mechanism, so this can disable 2FA logins",
	"ssh.permituserenvironment":      "login automation may depend on the supplied environment",
	"ssh.permittunnel":               "the host may intentionally provide an SSH VPN",
	"ssh.allowtcpforwarding":         "applications may depend on SSH tunnels",
	"ssh.maxsessions":                "multiplexed workflows may require several sessions",
	"ssh.allowagentforwarding":       "administrative hops may depend on agent forwarding",
	"accounts.local-banner":          "login warning wording needs organizational approval",
	"accounts.remote-banner":         "login warning wording needs organizational approval",
	"fileperms.compiler":             "development hosts legitimately need unprivileged compiler access",
	"ports.redis-bind":               "remote Redis clients may be intentional",
	"ports.redis-disable-config":     "administration workflows may require CONFIG",
	"sysctl.module-dccp":             "the host may use DCCP",
	"sysctl.module-sctp":             "the host may use SCTP",
	"sysctl.module-rds":              "the host may use RDS",
	"sysctl.module-tipc":             "the host may use TIPC",
	"sysctl.module-usbstorage":       "the host may need USB storage",
	"systemd.no-new-privileges":      "a service that deliberately escalates stops coming back, and it stops at the next restart rather than now — the drop-in is one edit, which is Auto's shape and nothing more",
	"systemd.protect-clock":          "only time-sync daemons legitimately need this off, and it stops at the next restart rather than now — the drop-in is one edit, which is Auto's shape and nothing more",
	"systemd.lock-personality":       "needing an alternate execution personality is rare, and it stops at the next restart rather than now — the drop-in is one edit, which is Auto's shape and nothing more",
	"systemd.restrict-suid-sgid":     "only a service that itself creates setuid/setgid files needs this off, and it stops at the next restart rather than now — the drop-in is one edit, which is Auto's shape and nothing more",
	"systemd.protect-kernel-logs":    "only a service that reads kernel logs directly needs this off, and it stops at the next restart rather than now — the drop-in is one edit, which is Auto's shape and nothing more",
	"systemd.protect-kernel-modules": "only a service that loads kernel modules at runtime needs this off, and it stops at the next restart rather than now — the drop-in is one edit, which is Auto's shape and nothing more",
}

// floorReview makes every fix in checkerDeclaresReview declare Review. It
// changes no behaviour: classify already took the stricter of the two.
func (r *Registry) floorReview() {
	for i, reg := range r.regs {
		if _, ok := checkerDeclaresReview[reg.pattern]; !ok {
			continue
		}
		build, why := reg.build, checkerDeclaresReview[reg.pattern]
		r.regs[i].build = func(f model.Finding) (Fix, error) {
			fx, err := build(f)
			if err != nil || fx.Kind != model.RemediationAuto {
				return fx, err
			}
			fx.Kind = model.RemediationReview
			// A lone Review action must say what it risks. Where the fix
			// had no Warning of its own, the reason it is Review is that.
			for j := range fx.Actions {
				if fx.Actions[j].Warning == "" {
					fx.Actions[j].Warning = sentence(why)
				}
			}
			return fx, nil
		}
	}
}

// sentence capitalises a table reason and ends it with a full stop, so it
// reads as the Warning it becomes.
func sentence(s string) string {
	if s == "" {
		return s
	}
	s = strings.ToUpper(s[:1]) + s[1:]
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}
