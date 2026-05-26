package fix

import (
	"fmt"
	"os/exec"
	"strings"
)

func registerSystemFixes(r *Registry) {
	execCmd := func(cmdline string) Action {
		return Action{
			Type:    ActionExec,
			Label:   fmt.Sprintf("Run: %s", cmdline),
			Command: strings.Fields(cmdline),
			Apply: func(ctx Context) error {
				args := strings.Fields(cmdline)
				return exec.Command(args[0], args[1:]...).Run()
			},
		}
	}
	fileEdit := func(path, label string, apply func(Context) error) Action {
		return Action{
			Type:     ActionEdit,
			Label:    label,
			FilePath: path,
			Apply:    apply,
		}
	}
	sysctlApply := func(param, value string) Action {
		return Action{
			Type:    ActionExec,
			Label:   fmt.Sprintf("Set sysctl %s=%s", param, value),
			Command: []string{"sysctl", "-w", fmt.Sprintf("%s=%s", param, value)},
			Apply: func(ctx Context) error {
				if err := exec.Command("sysctl", "-w", fmt.Sprintf("%s=%s", param, value)).Run(); err != nil {
					return err
				}
				return exec.Command("sh", "-c", fmt.Sprintf("echo '%s=%s' >> /etc/sysctl.conf", param, value)).Run()
			},
		}
	}

	// Auto (edit) — SSH
	r.Register(&Fix{
		FindingID: "lynis.AUTH-9286",
		Label:     "Disable SSH password authentication",
		Actions: []Action{fileEdit("/etc/ssh/sshd_config", "Disable SSH password authentication", func(ctx Context) error {
			return exec.Command("sed", "-i", `s/^#\?PasswordAuthentication.*/PasswordAuthentication no/`, "/etc/ssh/sshd_config").Run()
		})},
	})
	r.Register(&Fix{
		FindingID: "lynis.AUTH-9308",
		Label:     "Restrict root SSH login",
		Actions: []Action{fileEdit("/etc/ssh/sshd_config", "Restrict root SSH login", func(ctx Context) error {
			return exec.Command("sed", "-i", `s/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/`, "/etc/ssh/sshd_config").Run()
		})},
	})

	// Auto (exec) — File permissions
	r.Register(&Fix{
		FindingID: "lynis.FILE-6310",
		Label:     "Fix /etc/shadow permissions",
		Actions:   []Action{execCmd("chmod 640 /etc/shadow")},
	})
	r.Register(&Fix{
		FindingID: "lynis.FILE-6312",
		Label:     "Fix sshd_config permissions",
		Actions:   []Action{execCmd("chmod 600 /etc/ssh/sshd_config")},
	})
	r.Register(&Fix{
		FindingID: "lynis.FILE-6405",
		Label:     "Remove world-writable from file",
		Actions: []Action{{
			Type:    ActionExec,
			Label:   "Remove world-writable bit",
			Command: []string{"chmod", "o-w"},
			Apply: func(ctx Context) error {
				return exec.Command("chmod", "o-w", ctx.Finding.Evidence["path"]).Run()
			},
		}},
	})

	// Auto (exec) — Kernel
	r.Register(&Fix{
		FindingID: "lynis.KRNL-5780",
		Label:     "Disable IP forwarding",
		Actions: []Action{{
			Type:    ActionExec,
			Label:   "Disable IP forwarding",
			Warning: "May affect Docker networking or router functions.",
			Apply: func(ctx Context) error {
				if err := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=0").Run(); err != nil {
					return err
				}
				return exec.Command("sh", "-c", "echo 'net.ipv4.ip_forward=0' >> /etc/sysctl.conf").Run()
			},
		}},
	})
	r.Register(&Fix{
		FindingID: "lynis.KRNL-5820",
		Label:     "Disable ICMP redirect",
		Actions:   []Action{sysctlApply("net.ipv4.conf.all.accept_redirects", "0")},
	})
	r.Register(&Fix{
		FindingID: "lynis.NETW-2705",
		Label:     "Harden network stack",
		Actions: []Action{execCmd("sysctl -w net.ipv4.tcp_syncookies=1"),
			execCmd("sysctl -w net.ipv4.conf.all.rp_filter=1")},
	})

	// Auto (edit) — Banners
	r.Register(&Fix{
		FindingID: "lynis.BANN-7126",
		Label:     "Add legal banner to /etc/issue",
		Actions: []Action{fileEdit("/etc/issue", "Add banner to /etc/issue", func(ctx Context) error {
			return exec.Command("sh", "-c", `echo "Unauthorized access prohibited" > /etc/issue`).Run()
		})},
	})
	r.Register(&Fix{
		FindingID: "lynis.BANN-7130",
		Label:     "Add legal banner to /etc/motd",
		Actions: []Action{fileEdit("/etc/motd", "Add banner to /etc/motd", func(ctx Context) error {
			return exec.Command("sh", "-c", `echo "Unauthorized access prohibited" > /etc/motd`).Run()
		})},
	})

	// Auto (exec) — Accounts
	r.Register(&Fix{
		FindingID: "lynis.ACCT-9626",
		Label:     "Set password aging",
		Actions: []Action{{
			Type:    ActionExec,
			Label:   "Set password aging to 90 days",
			Command: []string{"chage", "-M", "90"},
			Apply: func(ctx Context) error {
				return exec.Command("chage", "-M", "90", ctx.Finding.Evidence["user"]).Run()
			},
		}},
	})

	// Review (≥2 actions) — Firewall
	r.Register(&Fix{
		FindingID: "lynis.FIRE-4512",
		Label:     "Enable firewall",
		Actions: []Action{
			execCmd("ufw --force enable"),
			{
				Type:    ActionExec,
				Label:   "Set iptables default deny policies",
				Command: []string{"sh", "-c", "iptables -P INPUT DROP; iptables -P FORWARD DROP"},
				Apply: func(ctx Context) error {
					return exec.Command("sh", "-c", "iptables -P INPUT DROP; iptables -P FORWARD DROP").Run()
				},
			},
		},
	})
	r.Register(&Fix{
		FindingID: "lynis.FIRE-4513",
		Label:     "Close open firewall ports",
		Actions: []Action{
			{
				Type:    ActionExec,
				Label:   "Block port with ufw",
				Command: []string{"ufw", "deny"},
				Apply: func(ctx Context) error {
					port := ctx.Finding.Evidence["port"]
					if port == "" {
						port = "22/tcp"
					}
					return exec.Command("ufw", "deny", port).Run()
				},
			},
			execCmd("iptables -A INPUT -p tcp --dport 22 -j DROP"),
		},
	})
	r.Register(&Fix{
		FindingID: "lynis.LOGG-2130",
		Label:     "Enable system logging",
		Actions: []Action{
			{
				Type:    ActionExec,
				Label:   "Install and enable rsyslog",
				Warning: "Requires internet access for package download.",
				Command: []string{"sh", "-c", `set -e; if command -v apt-get >/dev/null 2>&1; then apt-get install -y rsyslog && (systemctl enable --now rsyslog || service rsyslog start); elif command -v apk >/dev/null 2>&1; then apk add rsyslog && rc-update add rsyslog default && rc-service rsyslog start; elif command -v dnf >/dev/null 2>&1; then dnf install -y rsyslog && (systemctl enable --now rsyslog || service rsyslog start); else echo "No supported package manager" >&2; exit 1; fi`},
				Apply: func(ctx Context) error {
					script := `set -e
if command -v apt-get >/dev/null 2>&1; then
    apt-get install -y rsyslog && (systemctl enable --now rsyslog || service rsyslog start)
elif command -v apk >/dev/null 2>&1; then
    apk add rsyslog && rc-update add rsyslog default && rc-service rsyslog start
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y rsyslog && (systemctl enable --now rsyslog || service rsyslog start)
else
    echo "No supported package manager (apt/apk/dnf) found" >&2
    exit 1
fi`
					return exec.Command("sh", "-c", script).Run()
				},
			},
			{
				Type:    ActionEdit,
				Label:   "Set ForwardToSyslog=yes in journald.conf",
				Warning: "Requires systemd. Restart journald after applying.",
				Apply: func(ctx Context) error {
					if err := exec.Command("sed", "-i", `s/^#\?\s*ForwardToSyslog\s*=.*/ForwardToSyslog=yes/`, "/etc/systemd/journald.conf").Run(); err != nil {
						return err
					}
					return exec.Command("sh", "-c", `grep -q '^ForwardToSyslog=yes' /etc/systemd/journald.conf || echo 'ForwardToSyslog=yes' >> /etc/systemd/journald.conf`).Run()
				},
			},
		},
	})

	// Auto (exec) — LDAP
	r.Register(&Fix{
		FindingID: "lynis.AUTH-9265",
		Label:     "Configure LDAP authentication",
		Actions: []Action{{
			Type:    ActionExec,
			Label:   "Install LDAP packages",
			Warning: "Requires internet access. Post-install pam-auth-update may be needed.",
			Command: []string{"sh", "-c", `if command -v apt-get >/dev/null 2>&1; then apt-get install -y libnss-ldap pam-ldap; elif command -v dnf >/dev/null 2>&1; then dnf install -y nss-pam-ldapd; elif command -v apk >/dev/null 2>&1; then apk add nss-pam-ldapd; else echo "No supported package manager" >&2; exit 1; fi`},
			Apply: func(ctx Context) error {
				script := `if command -v apt-get >/dev/null 2>&1; then
    apt-get install -y libnss-ldap pam-ldap
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y nss-pam-ldapd
elif command -v apk >/dev/null 2>&1; then
    apk add nss-pam-ldapd
else
    echo "No supported package manager (apt/dnf/apk) found" >&2
    exit 1
fi`
				return exec.Command("sh", "-c", script).Run()
			},
		}},
	})

	// Auto (exec) — SELinux/AppArmor
	r.Register(&Fix{
		FindingID: "lynis.HRMN-6114",
		Label:     "Enable SELinux or AppArmor",
		Actions: []Action{{
			Type:    ActionExec,
			Label:   "Install SELinux/AppArmor packages",
			Warning: "Requires kernel support. May need reboot.",
			Command: []string{"sh", "-c", `if command -v apt-get >/dev/null 2>&1; then apt-get install -y selinux-policy-default apparmor; elif command -v dnf >/dev/null 2>&1; then dnf install -y selinux-policy; elif command -v apk >/dev/null 2>&1; then apk add apparmor; else echo "No supported package manager" >&2; exit 1; fi`},
			Apply: func(ctx Context) error {
				script := `if command -v apt-get >/dev/null 2>&1; then
    apt-get install -y selinux-policy-default apparmor
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y selinux-policy
elif command -v apk >/dev/null 2>&1; then
    apk add apparmor
else
    echo "No supported package manager (apt/dnf/apk) found" >&2
    exit 1
fi`
				return exec.Command("sh", "-c", script).Run()
			},
		}},
	})
}

// Lynis findings registered above.
