package fix

import (
	"fmt"

	"github.com/seolcu/hostveil/internal/model"
)

// registerSSH wires the SSH-domain fixes into the registry.
func registerSSH(r *Registry) {
	r.Register("ssh.emptypasswords", buildSSHAuto("PermitEmptyPasswords", "no", "Disable empty passwords",
		"Closes SSH login with a blank password — the one credential check an attacker never even has to guess.", ""))
	r.Register("ssh.maxauthtries", buildSSHAuto("MaxAuthTries", "3", "Lower MaxAuthTries to 3",
		"Throttles how many credential guesses a single SSH connection gets before it is dropped, slowing a brute-force attempt against this host specifically.", ""))
	r.Register("ssh.x11forwarding", buildSSHAuto("X11Forwarding", "no", "Disable X11 forwarding",
		"Removes an X11 forwarding channel that malware or an attacker with a foothold could otherwise ride out of the session.", ""))
	r.Register("ssh.passwordauth", buildSSHAuto("PasswordAuthentication", "no", "Disable password authentication",
		"Removes password-guessing as an SSH attack surface entirely — only a held key gets in from here on.",
		"Make sure key-based login works BEFORE applying this, or you may lock yourself out of SSH."))
	r.Register("ssh.rootlogin", buildRootLogin)
	r.Register("ssh.logingracetime", buildSSHAuto("LoginGraceTime", "60", "Lower LoginGraceTime to 60 seconds",
		"Shortens the window an unauthenticated connection can hold a login slot open, reducing exposure to connection-slot exhaustion.", ""))
	r.Register("ssh.gatewayports", buildSSHAuto("GatewayPorts", "no", "Bind remote-forwarded ports to loopback only",
		"Stops an `ssh -R` remote-forwarded port becoming reachable from other machines, closing a route around whatever this host's own firewall is doing.",
		"If you rely on `ssh -R` tunnels being reachable from other machines, this closes them to loopback."))
	r.Register("ssh.hostbasedauth", buildSSHAuto("HostbasedAuthentication", "no", "Disable host-based authentication",
		"Removes a trust-based login path that bypasses per-user keys entirely.",
		"If any user logs in via host-based trust rather than their own key, this removes that path."))
	r.Register("ssh.kbdinteractive", buildKbdInteractive)
	r.Register("ssh.permituserenvironment", buildSSHAuto("PermitUserEnvironment", "no", "Disable user-supplied SSH environments",
		"Stops a user's ~/.ssh/environment overriding the server process's own environment — a known way to hijack LD_PRELOAD or similar into a login session.",
		"Login automation that relies on ~/.ssh/environment will stop receiving those variables."))
	r.Register("ssh.permittunnel", buildSSHAuto("PermitTunnel", "no", "Disable SSH tun/tap tunnels",
		"Disables SSH's own VPN-like tun/tap tunneling, removing a route around whatever network controls this host is behind.",
		"Existing SSH VPN or tun/tap workflows will stop working."))
	r.Register("ssh.allowtcpforwarding", buildSSHAuto("AllowTcpForwarding", "no", "Disable SSH TCP forwarding",
		"Closes SSH's local, remote, and dynamic port forwarding — a common pivot and tunnel-out vector for anyone who gets a session on this host.",
		"Existing local, remote, and dynamic SSH tunnels will stop working."))
	r.Register("ssh.clientalivecountmax", buildSSHAuto("ClientAliveCountMax", "2", "Limit unanswered SSH keepalives",
		"Bounds how long a dead or hung session is held open, freeing the session slot instead of leaving it reserved indefinitely.", ""))
	r.Register("ssh.clientaliveinterval", buildSSHAuto("ClientAliveInterval", "300", "Probe idle SSH clients every five minutes",
		"Detects and disconnects idle or dead clients on a schedule, instead of leaving a session open for as long as the network happens to keep the TCP connection alive.",
		"Long-running idle sessions may be disconnected when their clients stop responding."))
	r.Register("ssh.fingerprinthash", buildSSHAuto("FingerprintHash", "sha256", "Use SHA-256 host-key fingerprints",
		"Uses a stronger hash for the host-key fingerprint shown to users and tooling verifying this server's identity.", ""))
	r.Register("ssh.ignorerhosts", buildSSHAuto("IgnoreRhosts", "yes", "Ignore legacy rhosts trust files",
		"Ignores legacy .rhosts trust files, closing a decades-old authentication bypass that has no place on a hardened host.", ""))
	r.Register("ssh.loglevel", buildSSHAuto("LogLevel", "VERBOSE", "Log SSH key fingerprints",
		"Logs the key fingerprint used on every login, giving the operator forensic evidence of exactly which key authenticated — not just that a login succeeded.", ""))
	r.Register("ssh.maxsessions", buildSSHAuto("MaxSessions", "2", "Limit multiplexed SSH sessions",
		"Caps multiplexed sessions per connection, limiting how much one compromised or stolen connection can do at once.",
		"Clients opening more than two sessions over one SSH connection will be refused."))
	r.Register("ssh.printlastlog", buildSSHAuto("PrintLastLog", "yes", "Show the previous login",
		"Shows the previous login on every connect, so a user has a chance to notice a login they did not make.", ""))
	r.Register("ssh.strictmodes", buildSSHAuto("StrictModes", "yes", "Enforce SSH login-file ownership",
		"Refuses to honor login files (keys, config) with loose ownership or permissions, closing a local tampering vector.", ""))
	r.Register("ssh.tcpkeepalive", buildSSHAuto("TCPKeepAlive", "no", "Disable TCP keepalives for SSH",
		"Stops relying on spoofable TCP keepalives for liveness, leaving ClientAliveInterval's encrypted check as the one source of truth for whether a session is still alive.",
		"Use ClientAliveInterval for encrypted liveness checks; dead connections may otherwise take longer to disappear from intermediate network devices."))
	r.Register("ssh.usedns", buildSSHAuto("UseDNS", "no", "Disable SSH reverse-DNS lookups",
		"Removes a DNS lookup from the login path — both a minor timing/DoS surface and a spoofing vector, for a lookup the login never actually needed.", ""))
	r.Register("ssh.allowagentforwarding", buildSSHAuto("AllowAgentForwarding", "no", "Disable SSH agent forwarding",
		"Stops a compromised host from riding a forwarded SSH agent to authenticate elsewhere as the user, using credentials that were never actually stored here.",
		"Existing workflows that hop through this host using a forwarded agent will stop working."))
}

// buildKbdInteractive disables keyboard-interactive authentication by
// setting whichever keyword is actually in force. The checker records it in
// the finding: sshd treats ChallengeResponseAuthentication as an alias for
// KbdInteractiveAuthentication and keeps the first value it sees for either,
// so writing the modern keyword into a file where the old alias already
// appears earlier would change nothing while claiming to have fixed it.
func buildKbdInteractive(f model.Finding) (Fix, error) {
	path, err := sshConfigPath(f)
	if err != nil {
		return Fix{}, err
	}
	key := f.Evidence["directive"]
	if key == "" {
		key = "KbdInteractiveAuthentication"
	}
	label := "Disable keyboard-interactive authentication"
	return Fix{
		Label: label,
		Kind:  model.RemediationAuto,
		Actions: []Action{sshEdit(path, label,
			"Closes the same password-equivalent prompt path PasswordAuthentication closes, for the "+
				"keyboard-interactive method some clients use instead.",
			"PAM-based one-time codes (2FA prompts) also use this mechanism — keep it enabled if your logins go through one.",
			key, "no")},
	}, nil
}

func sshConfigPath(f model.Finding) (string, error) {
	path := f.Evidence["config"]
	if path == "" {
		return "", fmt.Errorf("finding %s has no sshd_config path", f.ID)
	}
	return path, nil
}

// sshEdit builds an edit action that sets one sshd directive.
//
// Every SSH fix carries `sshd -t`, which parses the *effective* config —
// including whatever the Include directives pull in — and exits non-zero if
// sshd would refuse it. This is the domain where an unvalidated write is
// worst: sshd keeps serving from the config it already loaded, so a broken
// file looks like nothing at all until the next restart, and repairing it
// then needs the SSH access it just removed.
func sshEdit(path, label, benefit, warning, key, value string) Action {
	return Action{
		Label:   label,
		Benefit: benefit,
		Warning: warning,
		Kind:    ActionEdit,
		Path:    path,
		Transform: func(in []byte) ([]byte, error) {
			return setSSHDDirective(in, key, value), nil
		},
		VerifyCmd: []string{"sshd", "-t", "-f", VerifyPathToken},
	}
}

// buildSSHAuto returns a builder for a single-directive Auto fix.
func buildSSHAuto(key, value, label, benefit, warning string) Builder {
	return func(f model.Finding) (Fix, error) {
		path, err := sshConfigPath(f)
		if err != nil {
			return Fix{}, err
		}
		return Fix{
			Label:   label,
			Kind:    model.RemediationAuto,
			Actions: []Action{sshEdit(path, label, benefit, warning, key, value)},
		}, nil
	}
}

// buildRootLogin offers two independent alternatives for PermitRootLogin,
// so it is a Review fix.
func buildRootLogin(f model.Finding) (Fix, error) {
	path, err := sshConfigPath(f)
	if err != nil {
		return Fix{}, err
	}
	return Fix{
		Label: "Restrict root login over SSH",
		Kind:  model.RemediationReview,
		Actions: []Action{
			sshEdit(path, "Allow root only with an SSH key (prohibit-password)",
				"Keeps key-based root access working while removing the one thing root logins are "+
					"actually dangerous for: a guessable or stolen password.",
				"Keep a working key for root, or use a sudo user instead.", "PermitRootLogin", "prohibit-password"),
			sshEdit(path, "Disable root login entirely (no)",
				"Removes direct root login over SSH entirely, so compromising this host's authentication "+
					"means compromising a named, sudo-capable user instead of the one account every "+
					"attacker already knows the name of.",
				"Make sure another user can log in and use sudo before applying this.", "PermitRootLogin", "no"),
		},
	}, nil
}
