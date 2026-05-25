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
	prompt := func(label, desc string) Action {
		return Action{
			Type:        ActionPrompt,
			Label:       label,
			Description: desc,
			Apply: func(ctx Context) error {
				return fmt.Errorf("manual step: %s", desc)
			},
		}
	}
	sedEdit := func(pattern, file string) Action {
		return Action{
			Type:    ActionExec,
			Label:   fmt.Sprintf("sed -i '%s' %s", pattern, file),
			Command: []string{"sed", "-i", pattern, file},
			Apply: func(ctx Context) error {
				return exec.Command("sed", "-i", pattern, file).Run()
			},
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

	// Auto (exec) — SSH
	r.Register(&Fix{
		FindingID: "lynis.AUTH-9286",
		Label:     "Disable SSH password authentication",
		Warning:   "Ensure SSH key access is configured before applying. You may lose remote access.",
		Actions:   []Action{sedEdit(`s/^#\?PasswordAuthentication.*/PasswordAuthentication no/`, "/etc/ssh/sshd_config")},
	})
	r.Register(&Fix{
		FindingID: "lynis.AUTH-9308",
		Label:     "Restrict root SSH login",
		Warning:   "Requires sudo or SSH key access for root.",
		Actions:   []Action{sedEdit(`s/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/`, "/etc/ssh/sshd_config")},
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
		Actions:   []Action{execCmd("chmod o-w")},
	})

	// Auto (exec) — Kernel
	r.Register(&Fix{
		FindingID: "lynis.KRNL-5780",
		Label:     "Disable IP forwarding",
		Warning:   "May affect Docker networking or router functions.",
		Actions:   []Action{sysctlApply("net.ipv4.ip_forward", "0")},
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

	// Auto (exec) — Banners
	r.Register(&Fix{
		FindingID: "lynis.BANN-7126",
		Label:     "Add legal banner to /etc/issue",
		Actions:   []Action{execCmd("sh -c 'echo \"Unauthorized access prohibited\" > /etc/issue'")},
	})
	r.Register(&Fix{
		FindingID: "lynis.BANN-7130",
		Label:     "Add legal banner to /etc/motd",
		Actions:   []Action{execCmd("sh -c 'echo \"Unauthorized access prohibited\" > /etc/motd'")},
	})

	// Auto (exec) — Accounts
	r.Register(&Fix{
		FindingID: "lynis.ACCT-9626",
		Label:     "Set password aging",
		Actions:   []Action{execCmd("chage -M 90")},
	})

	// Review (≥2 actions) — Firewall
	r.Register(&Fix{
		FindingID: "lynis.FIRE-4512",
		Label:     "Enable firewall",
		Actions: []Action{
			execCmd("ufw --force enable"),
			execCmd("iptables -P INPUT DROP; iptables -P FORWARD DROP"),
		},
	})
	r.Register(&Fix{
		FindingID: "lynis.FIRE-4513",
		Label:     "Close open firewall ports",
		Actions: []Action{
			execCmd("ufw deny"),
			execCmd("iptables -A INPUT -p tcp --dport 22 -j DROP"),
		},
	})
	r.Register(&Fix{
		FindingID: "lynis.LOGG-2130",
		Label:     "Enable system logging",
		Actions: []Action{
			execCmd("apt-get install -y rsyslog && systemctl enable --now rsyslog"),
			prompt("Configure journald forwarding", "Edit /etc/systemd/journald.conf and set ForwardToSyslog=yes"),
		},
	})

	// Manual (prompt only)
	r.Register(&Fix{
		FindingID: "lynis.AUTH-9265",
		Label:     "Configure LDAP authentication",
		Actions:   []Action{prompt("Set up LDAP auth manually", "Install libnss-ldap and pam-ldap, then run 'pam-auth-update'.")},
	})
	r.Register(&Fix{
		FindingID: "lynis.HRMN-6114",
		Label:     "Enable SELinux or AppArmor",
		Actions:   []Action{prompt("Install SELinux/AppArmor profile", "Install the package and ensure the LSM is enabled in kernel cmdline.")},
	})
}

// Lynis findings registered above.
