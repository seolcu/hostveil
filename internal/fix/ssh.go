package fix

import (
	"fmt"

	"github.com/seolcu/hostveil/internal/model"
)

// registerSSH wires the SSH-domain fixes into the registry.
func registerSSH(r *Registry) {
	r.Register("ssh.emptypasswords", buildSSHAuto("PermitEmptyPasswords", "no", "Disable empty passwords", ""))
	r.Register("ssh.maxauthtries", buildSSHAuto("MaxAuthTries", "4", "Lower MaxAuthTries to 4", ""))
	r.Register("ssh.x11forwarding", buildSSHAuto("X11Forwarding", "no", "Disable X11 forwarding", ""))
	r.Register("ssh.passwordauth", buildSSHAuto("PasswordAuthentication", "no", "Disable password authentication",
		"Make sure key-based login works BEFORE applying this, or you may lock yourself out of SSH."))
	r.Register("ssh.rootlogin", buildRootLogin)
}

func sshConfigPath(f model.Finding) (string, error) {
	path := f.Evidence["config"]
	if path == "" {
		return "", fmt.Errorf("finding %s has no sshd_config path", f.ID)
	}
	return path, nil
}

// sshEdit builds an edit action that sets one sshd directive.
func sshEdit(path, label, warning, key, value string) Action {
	return Action{
		Label:   label,
		Warning: warning,
		Kind:    ActionEdit,
		Path:    path,
		Transform: func(in []byte) ([]byte, error) {
			return setSSHDDirective(in, key, value), nil
		},
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
