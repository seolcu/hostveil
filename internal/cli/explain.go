package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/store"
)

var (
	explainFlagAI bool
)

func newExplainCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "explain <finding-id-or-rule-id>",
		Short: "Explain a finding or rule in plain language",
		Args:  cobra.ExactArgs(1),
		RunE:  runExplain,
	}
	cmd.Flags().BoolVar(&explainFlagAI, "ai", false, "use the configured AI provider (opt-in)")
	return cmd
}

// runExplain prints a structured plain-language explanation of a
// finding or a rule_id. The v3.0.0-alpha implementation is
// table-driven: each known rule_id has a built-in explanation; an
// unknown id is explained as "no built-in explanation yet".
//
// The --ai flag is reserved for v3.x: when set, the explanation is
// sent to the configured AI provider. The v3.0.0-alpha AI layer is
// not yet wired, so --ai currently prints a one-line message and
// falls back to the built-in explanation.
func runExplain(cmd *cobra.Command, args []string) error {
	paths, err := store.Resolve()
	if err != nil {
		return err
	}
	if err := paths.EnsureDirs(); err != nil {
		return err
	}
	s, err := store.Open(paths.StateDB)
	if err != nil {
		return fmt.Errorf("open state.db: %w", err)
	}
	defer s.Close()

	if explainFlagAI {
		fmt.Fprintln(os.Stderr, "hostveil: --ai is reserved for the v3.x AI layer; using the built-in explanation")
	}

	// Try the finding first.
	f, ferr := findFinding(s, args[0])
	if ferr == nil {
		printFindingExplanation(f)
		return nil
	}
	// Fall back to a rule_id-based explanation.
	ex, ok := ruleExplanations[args[0]]
	if !ok {
		fmt.Fprintf(os.Stderr, "no built-in explanation for rule %q; the v3.x AI layer will fill this in\n", args[0])
		return nil
	}
	fmt.Fprintf(os.Stderr, "%s: %s\n\n%s\n", args[0], ex.Title, ex.Body)
	return nil
}

func printFindingExplanation(f model.Finding) {
	ex, ok := ruleExplanations[f.RuleID]
	if !ok {
		fmt.Fprintf(os.Stderr, "%s: %s\n\n(no built-in explanation yet for rule %s)\n",
			f.RuleID, f.Title, f.RuleID)
		return
	}
	fmt.Fprintf(os.Stderr, "%s: %s\n\n%s\n", f.RuleID, f.Title, ex.Body)
	if f.FirstSeenAt.Unix() > 0 {
		fmt.Fprintf(os.Stderr, "First seen: %s\n", f.FirstSeenAt.Format(time.RFC3339))
	}
	if len(f.EntityRefs) > 0 {
		parts := make([]string, 0, len(f.EntityRefs))
		for _, r := range f.EntityRefs {
			parts = append(parts, r.Display)
		}
		fmt.Fprintf(os.Stderr, "Locations: %s\n", strings.Join(parts, ", "))
	}
}

// Explanation is the human-readable form of a rule_id.
type Explanation struct {
	Title string
	Body  string
}

// ruleExplanations is the v3.0.0-alpha built-in catalog. Each rule
// in scope (per the spec) has a short title and a longer plain-
// language body. The v3.x release replaces this with the real
// per-rule catalog; the shape is locked.
var ruleExplanations = map[string]Explanation{
	"ssh.permit_root_login.allow": {
		Title: "Root login is allowed over SSH",
		Body: `If the root user can log in directly over SSH, anyone
who reaches your SSH port can try to log in as root. A leaked,
guessed, or brute-forced root password gives the attacker full
control of the host with no further escalation.

Fix: set "PermitRootLogin no" in /etc/ssh/sshd_config and reload
sshd. If you need root SSH access, use an unprivileged user plus
sudo, or use an SSH key with the "from=" option in authorized_keys.`,
	},
	"ssh.password_auth.only": {
		Title: "Password authentication is the only available method",
		Body: `Passwords can be guessed, phished, or leaked. SSH keys
are an order of magnitude stronger and do not suffer from password
reuse. Disabling password authentication does not prevent you
from using a password-protected key, which combines the convenience
of a passphrase with the strength of a key.

Fix: set "PasswordAuthentication no" once every account on the
host has at least one key installed in ~/.ssh/authorized_keys.`,
	},
	"ssh.protocol.legacy": {
		Title: "Legacy SSH protocol version is enabled",
		Body: `SSHv1 has well-known cryptographic weaknesses and is
considered broken. The OpenSSH server defaults to protocol 2 when
the Protocol directive is absent; an explicit "Protocol 2" is a
defensive assertion that protects against future regressions.

Fix: set "Protocol 2" in /etc/ssh/sshd_config and reload sshd.`,
	},
	"docker.container.runs_as_root": {
		Title: "Container runs as root",
		Body: `When a container runs as root, a container escape lands
the attacker as root on the host. Running as a dedicated
non-root user limits the blast radius.

Fix: add a "user:" directive to the container (or "USER" in
the Dockerfile) that switches to a non-root account.`,
	},
	"docker.container.privileged": {
		Title: "Container runs in privileged mode",
		Body: `--privileged disables most of the container's security
boundaries. It is almost never what you want.

Fix: drop --privileged. If the workload truly needs special
capabilities, grant only the specific capabilities it needs
with --cap-add.`,
	},
	"docker.port.exposed_public": {
		Title: "Container exposes a port on all interfaces",
		Body: `Binding to 0.0.0.0 publishes the port to every network
the host can reach. If the host is on the public internet, that
means anyone on the internet.

Fix: bind to 127.0.0.1 when the port is for local development, or
publish the port behind a reverse proxy with authentication.`,
	},
	"docker.compose.latest_tag": {
		Title: "Image is pinned to the ':latest' tag",
		Body: `The :latest tag floats: today's "latest" is not
tomorrow's. A build that passes today can break tomorrow without
warning.

Fix: pin the image to an immutable digest (image@sha256:...) or
to a specific version tag, and re-deploy on upgrades.`,
	},
	"reverse_proxy.server_tokens": {
		Title: "Reverse proxy leaks the server version",
		Body: `Exposing the server version tells an attacker exactly
which CVEs apply. server_tokens off (nginx) or removing the Server
header (caddy) keeps the response neutral.

Fix: nginx: add "server_tokens off;" to the http {} block. caddy:
add a "Server" header set to an empty value.`,
	},
	"reverse_proxy.security_headers": {
		Title: "Missing security response header",
		Body: `Several response headers (X-Content-Type-Options,
X-Frame-Options, Referrer-Policy, Strict-Transport-Security)
mitigate common attack classes at zero functional cost.

Fix: add the missing header to your reverse proxy config. Most
proxies have a one-line directive for each.`,
	},
	"hardening_firewall.ufw_inactive": {
		Title: "UFW is installed but inactive",
		Body: `A firewall with a deny-by-default policy is the last
line of defense when a service accidentally exposes a port. UFW
not running means every port on the host is reachable from every
network the host can see.

Fix: enable UFW with "sudo ufw enable". Start with the default
deny policy and add explicit allow rules for the services you
need.`,
	},
	"hardening_sysctl.baseline": {
		Title: "sysctl baseline value is not set",
		Body: `A handful of sysctl keys defend against IP spoofing,
source routing, ICMP redirects, and a few other network-level
attacks. The expected values are locked in the spec; the
detected value diverges.

Fix: write the value to a file under /etc/sysctl.d/ (e.g.
/etc/sysctl.d/99-hostveil.conf) and run "sudo sysctl --system".
The change persists across reboots.`,
	},
	"hardening_updates.pending": {
		Title: "Security updates are pending",
		Body: `Every day that a security update goes unapplied is a
day the host is known-vulnerable. unattended-upgrades + a
reboot policy keeps the host current without manual work.

Fix: apply the pending updates ("sudo apt upgrade --security" or
"sudo dnf update --security"), and ensure unattended-upgrades is
configured to apply security updates automatically.`,
	},
}
