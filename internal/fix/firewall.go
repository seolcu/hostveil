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
}

func buildEnableFirewall(f model.Finding) (Fix, error) {
	// No port, no fix. A firewall enabled without knowing which port to keep
	// open is the lockout this refused to risk for years, and "I could not
	// tell" must not quietly become "22".
	raw := f.Evidence["ssh_port"]
	port, err := strconv.Atoi(raw)
	if err != nil || port <= 0 || port > 65535 {
		return Fix{}, fmt.Errorf("finding %s does not name the port sshd is listening on, "+
			"so enabling a firewall could lock the operator out", f.ID)
	}
	if !strings.Contains(f.Evidence["available"], "ufw") {
		return Fix{}, fmt.Errorf("finding %s reports no ufw, and the other front-ends "+
			"take rules this fix cannot write safely", f.ID)
	}
	p := strconv.Itoa(port)
	return Fix{
		FindingID: f.ID,
		Label:     "Enable ufw, allowing SSH on port " + p + " first",
		// Declared Auto — one mechanical action — and demoted to Review by
		// EffectiveKind because it is exec, which is the same route
		// updates.disabled takes. Validate reserves the Review kind for
		// fixes with two or more *alternatives* to choose between, and this
		// has one procedure whose steps are ordered, not a choice.
		Kind: model.RemediationAuto,
		Actions: []Action{{
			Label: "Allow SSH on " + p + "/tcp, then enable ufw with a default-deny inbound policy",
			Warning: "Every inbound port except " + p + "/tcp stops being reachable the moment this " +
				"runs, including anything a container publishes. There is no rollback checkpoint — " +
				"exec fixes are not file-backed — so undoing it means `ufw disable` by hand.",
			Kind: ActionExec,
			Commands: [][]string{
				{"ufw", "allow", p + "/tcp"},
				{"ufw", "--force", "enable"},
			},
		}},
	}, nil
}
