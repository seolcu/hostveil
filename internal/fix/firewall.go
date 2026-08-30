package fix

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/seolcu/hostveil/internal/model"
)

// registerFirewall wires the "turn the firewall on" fix.
//
// This was declined for a long time, and the reason was right: enabling a
// default-deny policy on a box you reached over SSH drops every connection no
// rule allows — including the one issuing the command — and an exec fix
// writes no checkpoint, so a lockout has no undo. The finding's how-to-fix
// told the operator to allow their SSH port first, which is advice a person
// can follow in order and a tool could not, because the checker recorded no
// port.
//
// It records one now, read from the kernel's socket table: the port sshd is
// actually serving on, not the one its config claims. That is the whole
// difference. The fix allows that port and only then enables the firewall,
// as two commands of a single action, in that order.
//
// It stays Review. The commands cannot be rolled back, the host's other
// services stop being reachable the moment the policy takes effect, and both
// of those are things an operator should decide rather than discover. What
// changes is that hostveil can now carry it out, instead of describing it.
func registerFirewall(r *Registry) {
	r.Register("firewall.inactive", buildEnableFirewall)
	r.Register("firewall.default-allow", buildFixDefaultAllow)
}

func buildEnableFirewall(f model.Finding) (Fix, error) {
	// No port, no fix. A firewall enabled without knowing which port to keep
	// open is the lockout this refused to risk for years, and "I could not
	// tell" must not quietly become "22".
	// Every port sshd is listening on, not the first. Two at once is how an
	// operator changes the SSH port without locking themselves out — the old
	// and the new both open until the new one is proven — and allowing one of
	// them before a default-deny policy severs the other, with no checkpoint.
	ports, err := parseSSHPorts(f.Evidence["ssh_port"])
	if err != nil {
		return Fix{}, fmt.Errorf("finding %s does not name the port(s) sshd is listening on, "+
			"so enabling a firewall could lock the operator out: %w", f.ID, err)
	}
	if !strings.Contains(f.Evidence["available"], "ufw") {
		return Fix{}, fmt.Errorf("finding %s reports no ufw, and the other front-ends "+
			"take rules this fix cannot write safely", f.ID)
	}
	list := make([]string, 0, len(ports))
	for _, p := range ports {
		list = append(list, strconv.Itoa(p))
	}
	spelled := strings.Join(list, " and ")
	allow := make([][]string, 0, len(list)+1)
	for _, p := range list {
		allow = append(allow, []string{"ufw", "allow", p + "/tcp"})
	}
	allow = append(allow, []string{"ufw", "--force", "enable"})

	return Fix{
		FindingID: f.ID,
		Label:     "Enable ufw, allowing SSH on port " + spelled + " first",
		// Declared Auto — one mechanical action — and demoted to Review by
		// EffectiveKind because it is exec, which is the same route
		// updates.disabled takes. Validate reserves the Review kind for
		// fixes with two or more *alternatives* to choose between, and this
		// has one procedure whose steps are ordered, not a choice.
		Kind: model.RemediationAuto,
		Actions: []Action{{
			Label: "Allow SSH on " + spelled + "/tcp, then enable ufw with a default-deny inbound policy",
			Benefit: "Turns on default-deny, so only the ports hostveil confirmed sshd is actually " +
				"listening on stay reachable — everything else stops accepting connections from off this host.",
			Warning: "Every inbound port except " + spelled + "/tcp stops being reachable the moment this " +
				"runs, including anything a container publishes. There is no rollback checkpoint — " +
				"exec fixes are not file-backed — so undoing it means `ufw disable` by hand.",
			Kind:     ActionExec,
			Commands: allow,
		}},
	}, nil
}

// buildFixDefaultAllow flips a running firewall's default inbound policy
// from allow to deny. It is buildEnableFirewall's fix applied to a firewall
// that is already running rather than absent — same evidence, same ordering
// (allow SSH first, then tighten the policy), same reason it stays Review —
// restricted to ufw for the same reason: firewalld's target flip has no
// registered fix yet.
func buildFixDefaultAllow(f model.Finding) (Fix, error) {
	ports, err := parseSSHPorts(f.Evidence["ssh_port"])
	if err != nil {
		return Fix{}, fmt.Errorf("finding %s does not name the port(s) sshd is listening on, "+
			"so tightening the firewall's default policy could lock the operator out: %w", f.ID, err)
	}
	if f.Evidence["firewall"] != "ufw" {
		return Fix{}, fmt.Errorf("finding %s reports %q, and only ufw's default policy "+
			"has a registered fix", f.ID, f.Evidence["firewall"])
	}
	list := make([]string, 0, len(ports))
	for _, p := range ports {
		list = append(list, strconv.Itoa(p))
	}
	spelled := strings.Join(list, " and ")
	commands := make([][]string, 0, len(list)+2)
	for _, p := range list {
		commands = append(commands, []string{"ufw", "allow", p + "/tcp"})
	}
	commands = append(commands, []string{"ufw", "default", "deny", "incoming"}, []string{"ufw", "reload"})

	return Fix{
		FindingID: f.ID,
		Label:     "Allow SSH on port " + spelled + ", then deny inbound traffic by default",
		// Same shape as firewall.inactive: one ordered procedure of exec
		// commands, declared Auto and floored to Review by EffectiveKind.
		Kind: model.RemediationAuto,
		Actions: []Action{{
			Label: "Allow SSH on " + spelled + "/tcp, then set ufw's default inbound policy to deny",
			Benefit: "Flips a firewall that is already running from allow-by-default to deny-by-default, " +
				"closing every port nothing has explicitly opened on a host where a firewall was already " +
				"assumed to be doing that job.",
			Warning: "Every inbound port except " + spelled + "/tcp stops being reachable the moment this " +
				"runs, including anything a container publishes. There is no rollback checkpoint — " +
				"exec fixes are not file-backed — so undoing it means `ufw default allow incoming` by hand.",
			Kind:     ActionExec,
			Commands: commands,
		}},
	}, nil
}

// parseSSHPorts reads the comma-separated list of ports the checker observed
// sshd listening on. Every one has to be a real port: a list hostveil cannot
// fully parse is one it cannot fully allow, and allowing the part it
// understood before a default-deny policy is how the other part gets severed.
func parseSSHPorts(raw string) ([]int, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("no port recorded")
	}
	var out []int
	for _, field := range strings.Split(raw, ",") {
		port, err := strconv.Atoi(strings.TrimSpace(field))
		if err != nil || port <= 0 || port > 65535 {
			return nil, fmt.Errorf("%q is not a port", field)
		}
		out = append(out, port)
	}
	return out, nil
}
