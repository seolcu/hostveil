package fix

import (
	"fmt"

	"github.com/seolcu/hostveil/internal/model"
)

// registerSSH wires the SSH-domain fixes into the registry.
func registerSSH(r *Registry) {
	r.Register("ssh.emptypasswords", buildSSHAuto("PermitEmptyPasswords", "no", "Disable empty passwords", ""))
	r.Register("ssh.maxauthtries", buildSSHAuto("MaxAuthTries", "3", "Lower MaxAuthTries to 3", ""))
	r.Register("ssh.x11forwarding", buildSSHAuto("X11Forwarding", "no", "Disable X11 forwarding", ""))
	r.Register("ssh.passwordauth", buildSSHAuto("PasswordAuthentication", "no", "Disable password authentication",
		"Make sure key-based login works BEFORE applying this, or you may lock yourself out of SSH."))
	r.Register("ssh.rootlogin", buildRootLogin)
	r.Register("ssh.logingracetime", buildSSHAuto("LoginGraceTime", "60", "Lower LoginGraceTime to 60 seconds", ""))
	r.Register("ssh.gatewayports", buildSSHAuto("GatewayPorts", "no", "Bind remote-forwarded ports to loopback only",
		"If you rely on `ssh -R` tunnels being reachable from other machines, this closes them to loopback."))
	r.Register("ssh.hostbasedauth", buildSSHAuto("HostbasedAuthentication", "no", "Disable host-based authentication",
		"If any user logs in via host-based trust rather than their own key, this removes that path."))
	r.Register("ssh.kbdinteractive", buildKbdInteractive)
	r.Register("ssh.permituserenvironment", buildSSHAuto("PermitUserEnvironment", "no", "Disable user-supplied SSH environments", "Login automation that relies on ~/.ssh/environment will stop receiving those variables."))
	r.Register("ssh.permittunnel", buildSSHAuto("PermitTunnel", "no", "Disable SSH tun/tap tunnels", "Existing SSH VPN or tun/tap workflows will stop working."))
	r.Register("ssh.allowtcpforwarding", buildSSHAuto("AllowTcpForwarding", "no", "Disable SSH TCP forwarding", "Existing local, remote, and dynamic SSH tunnels will stop working."))
	r.Register("ssh.clientalivecountmax", buildSSHAuto("ClientAliveCountMax", "2", "Limit unanswered SSH keepalives", ""))
	r.Register("ssh.clientaliveinterval", buildSSHAuto("ClientAliveInterval", "300", "Probe idle SSH clients every five minutes", "Long-running idle sessions may be disconnected when their clients stop responding."))
	r.Register("ssh.fingerprinthash", buildSSHAuto("FingerprintHash", "sha256", "Use SHA-256 host-key fingerprints", ""))
	r.Register("ssh.ignorerhosts", buildSSHAuto("IgnoreRhosts", "yes", "Ignore legacy rhosts trust files", ""))
	r.Register("ssh.loglevel", buildSSHAuto("LogLevel", "VERBOSE", "Log SSH key fingerprints", ""))
	r.Register("ssh.maxsessions", buildSSHAuto("MaxSessions", "2", "Limit multiplexed SSH sessions", "Clients opening more than two sessions over one SSH connection will be refused."))
	r.Register("ssh.printlastlog", buildSSHAuto("PrintLastLog", "yes", "Show the previous login", ""))
	r.Register("ssh.strictmodes", buildSSHAuto("StrictModes", "yes", "Enforce SSH login-file ownership", ""))
	r.Register("ssh.tcpkeepalive", buildSSHAuto("TCPKeepAlive", "no", "Disable TCP keepalives for SSH", "Use ClientAliveInterval for encrypted liveness checks; dead connections may otherwise take longer to disappear from intermediate network devices."))
	r.Register("ssh.usedns", buildSSHAuto("UseDNS", "no", "Disable SSH reverse-DNS lookups", ""))
	r.Register("ssh.allowagentforwarding", buildSSHAuto("AllowAgentForwarding", "no", "Disable SSH agent forwarding", "Existing workflows that hop through this host using a forwarded agent will stop working."))
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
func sshEdit(path, label, warning, key, value string) Action {
	return Action{
		Label:   label,
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
func buildSSHAuto(key, value, label, warning string) Builder {
	return func(f model.Finding) (Fix, error) {
		path, err := sshConfigPath(f)
		if err != nil {
			return Fix{}, err
		}
		return Fix{
			Label:   label,
			Kind:    model.RemediationAuto,
			Actions: []Action{sshEdit(path, label, warning, key, value)},
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
				"Keep a working key for root, or use a sudo user instead.", "PermitRootLogin", "prohibit-password"),
			sshEdit(path, "Disable root login entirely (no)",
				"Make sure another user can log in and use sudo before applying this.", "PermitRootLogin", "no"),
		},
	}, nil
}
