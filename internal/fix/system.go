package fix

import (
	"fmt"
	"os/exec"
	"path/filepath"
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
				entry := fmt.Sprintf("%s=%s", param, value)
				existsErr := exec.Command("sh", "-c", fmt.Sprintf("grep -q '^%s=' /etc/sysctl.conf", param)).Run()
				if existsErr != nil {
					return exec.Command("sh", "-c", fmt.Sprintf("echo '%s' >> /etc/sysctl.conf", entry)).Run()
				}
				return exec.Command("sh", "-c", fmt.Sprintf("sed -i 's/^#*\\s*%s\\s*=.*/%s/' /etc/sysctl.conf", param, entry)).Run()
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
				p := sanitizePath(ctx.Finding.Evidence["path"])
				if p == "" {
					return fmt.Errorf("invalid or dangerous path: %q", ctx.Finding.Evidence["path"])
				}
				return exec.Command("chmod", "o-w", p).Run()
			},
		}},
	})

	// Auto (exec) — Kernel
	r.Register(&Fix{
		FindingID: "lynis.KRNL-5780",
		Label:     "Disable IP forwarding",
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

	// Auto (edit) — Banners
	r.Register(&Fix{
			FindingID: "lynis.BANN-7126",
			Label:     "Add legal banner to /etc/issue",
			Actions: []Action{fileEdit("/etc/issue", "Add banner to /etc/issue", func(ctx Context) error {
				return exec.Command("sh", "-c", `grep -q "Unauthorized access prohibited" /etc/issue 2>/dev/null || echo "Unauthorized access prohibited" >> /etc/issue`).Run()
			})},
		})
		r.Register(&Fix{
			FindingID: "lynis.BANN-7130",
			Label:     "Add legal banner to /etc/motd",
			Actions: []Action{fileEdit("/etc/motd", "Add banner to /etc/motd", func(ctx Context) error {
				return exec.Command("sh", "-c", `grep -q "Unauthorized access prohibited" /etc/motd 2>/dev/null || echo "Unauthorized access prohibited" >> /etc/motd`).Run()
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
				u := sanitizeUser(ctx.Finding.Evidence["user"])
				if u == "" {
					return fmt.Errorf("invalid username: %q", ctx.Finding.Evidence["user"])
				}
				return exec.Command("chage", "-M", "90", u).Run()
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
					sp := sanitizePort(port)
					if sp == "" {
						return fmt.Errorf("invalid port: %q", port)
					}
					return exec.Command("ufw", "deny", sp).Run()
				},
			},
			{
				Type:  ActionExec,
				Label: "Block port with iptables",
				Apply: func(ctx Context) error {
					raw := ctx.Finding.Evidence["port"]
					if raw == "" {
						raw = "22"
					}
					sp := sanitizePort(raw)
					if sp == "" {
						return fmt.Errorf("invalid port: %q", raw)
					}
					return exec.Command("iptables", "-A", "INPUT", "-p", "tcp", "--dport", sp, "-j", "DROP").Run()
				},
			},
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

	// Auto (exec) — Kernel hardening (sysctl)
	r.Register(&Fix{
		FindingID: "lynis.KRNL-5830",
		Label:     "Disable source routed packets",
		Actions:   []Action{sysctlApply("net.ipv4.conf.all.accept_source_route", "0")},
	})
	r.Register(&Fix{
		FindingID: "lynis.KRNL-5840",
		Label:     "Disable send redirects",
		Actions:   []Action{sysctlApply("net.ipv4.conf.all.send_redirects", "0")},
	})
	r.Register(&Fix{
		FindingID: "lynis.KRNL-5860",
		Label:     "Enable TCP SYN cookies",
		Actions:   []Action{sysctlApply("net.ipv4.tcp_syncookies", "1")},
	})
	r.Register(&Fix{
		FindingID: "lynis.KRNL-5870",
		Label:     "Enable reverse path filtering",
		Actions:   []Action{sysctlApply("net.ipv4.conf.all.rp_filter", "1")},
	})
	r.Register(&Fix{
		FindingID: "lynis.KRNL-5880",
		Label:     "Ignore ICMP echo broadcasts",
		Actions:   []Action{sysctlApply("net.ipv4.icmp_echo_ignore_broadcasts", "1")},
	})
	r.Register(&Fix{
		FindingID: "lynis.KRNL-5890",
		Label:     "Ignore bogus ICMP errors",
		Actions:   []Action{sysctlApply("net.ipv4.icmp_ignore_bogus_error_responses", "1")},
	})
	r.Register(&Fix{
		FindingID: "lynis.KRNL-5930",
		Label:     "Disable TCP timestamps",
		Actions:   []Action{sysctlApply("net.ipv4.tcp_timestamps", "0")},
	})

	// Auto (exec) — File permissions
	r.Register(&Fix{
		FindingID: "lynis.FILE-6300",
		Label:     "Restrict /etc/passwd permissions",
		Actions:   []Action{execCmd("chmod 644 /etc/passwd")},
	})
	r.Register(&Fix{
		FindingID: "lynis.FILE-6304",
		Label:     "Restrict /etc/group permissions",
		Actions:   []Action{execCmd("chmod 644 /etc/group")},
	})

	// Auto (edit) — Authentication
	r.Register(&Fix{
		FindingID: "lynis.AUTH-9208",
		Label:     "Disable SSH protocol 1",
		Actions: []Action{fileEdit("/etc/ssh/sshd_config", "Set SSH Protocol 2", func(ctx Context) error {
			return exec.Command("sh", "-c", `grep -q '^Protocol' /etc/ssh/sshd_config && sed -i 's/^Protocol.*/Protocol 2/' /etc/ssh/sshd_config || echo 'Protocol 2' >> /etc/ssh/sshd_config`).Run()
		})},
	})
	r.Register(&Fix{
		FindingID: "lynis.AUTH-9222",
		Label:     "Set password minimum days",
		Actions: []Action{fileEdit("/etc/login.defs", "Set PASS_MIN_DAYS", func(ctx Context) error {
			return exec.Command("sh", "-c", `grep -q '^PASS_MIN_DAYS' /etc/login.defs && sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs || echo 'PASS_MIN_DAYS 1' >> /etc/login.defs`).Run()
		})},
	})
	r.Register(&Fix{
		FindingID: "lynis.AUTH-9223",
		Label:     "Set password maximum days",
		Actions: []Action{fileEdit("/etc/login.defs", "Set PASS_MAX_DAYS", func(ctx Context) error {
			return exec.Command("sh", "-c", `grep -q '^PASS_MAX_DAYS' /etc/login.defs && sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs || echo 'PASS_MAX_DAYS 90' >> /etc/login.defs`).Run()
		})},
	})
	r.Register(&Fix{
		FindingID: "lynis.AUTH-9262",
		Label:     "Configure sudo timestamp timeout",
		Actions: []Action{fileEdit("/etc/sudoers.d/hv-timeout", "Set sudo timestamp timeout", func(ctx Context) error {
			return exec.Command("sh", "-c", `echo 'Defaults timestamp_timeout=5' > /etc/sudoers.d/hv-timeout && chmod 440 /etc/sudoers.d/hv-timeout`).Run()
		})},
	})

	// Auto (exec) — Boot security
	r.Register(&Fix{
		FindingID: "lynis.BOOT-5120",
		Label:     "Set bootloader password",
		Actions: []Action{{
			Type:    ActionExec,
			Label:   "Set GRUB bootloader password",
			Warning: "Requires GRUB. Verify bootloader config after applying.",
			Command: []string{"sh", "-c", `grub2-set-password 2>/dev/null || grub-set-password 2>/dev/null || echo "GRUB password tool not found" >&2`},
			Apply: func(ctx Context) error {
				return exec.Command("sh", "-c", `if command -v grub2-set-password >/dev/null 2>&1; then grub2-set-password; elif command -v grub-set-password >/dev/null 2>&1; then grub-set-password; else echo "GRUB password tool not available" >&2; exit 1; fi`).Run()
			},
		}},
	})

	// Auto (exec) — Logging
	r.Register(&Fix{
		FindingID: "lynis.LOGG-2100",
		Label:     "Enable syslog-ng or rsyslog",
		Actions: []Action{{
			Type:    ActionExec,
			Label:   "Install and enable rsyslog",
			Warning: "Requires internet access for package download.",
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
		}},
	})

	// Auto (exec) — Time sync
	r.Register(&Fix{
		FindingID: "lynis.TIME-3106",
		Label:     "Configure NTP/Chrony",
		Actions: []Action{{
			Type:    ActionExec,
			Label:   "Install and enable chrony",
			Warning: "Requires internet access. Configure NTP servers after install.",
			Apply: func(ctx Context) error {
				script := `set -e
if command -v apt-get >/dev/null 2>&1; then
    apt-get install -y chrony && (systemctl enable --now chrony || service chrony start)
elif command -v apk >/dev/null 2>&1; then
    apk add chrony && rc-update add chrony default && rc-service chrony start
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y chrony && (systemctl enable --now chrony || service chrony start)
else
    echo "No supported package manager (apt/apk/dnf) found" >&2
    exit 1
fi`
				return exec.Command("sh", "-c", script).Run()
			},
		}},
	})

	// Auto (edit) — Additional SSH hardening
	r.Register(&Fix{
		FindingID: "lynis.AUTH-9216",
		Label:     "Set SSH MaxAuthTries",
		Actions: []Action{fileEdit("/etc/ssh/sshd_config", "Set MaxAuthTries", func(ctx Context) error {
			return exec.Command("sh", "-c", `grep -q '^MaxAuthTries' /etc/ssh/sshd_config && sed -i 's/^MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config || echo 'MaxAuthTries 3' >> /etc/ssh/sshd_config`).Run()
		})},
	})
	r.Register(&Fix{
		FindingID: "lynis.AUTH-9229",
		Label:     "Set SSH ClientAliveInterval",
		Actions: []Action{fileEdit("/etc/ssh/sshd_config", "Set ClientAliveInterval", func(ctx Context) error {
			return exec.Command("sh", "-c", `grep -q '^ClientAliveInterval' /etc/ssh/sshd_config && sed -i 's/^ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config || echo 'ClientAliveInterval 300' >> /etc/ssh/sshd_config`).Run()
		})},
	})
	r.Register(&Fix{
		FindingID: "lynis.AUTH-9230",
		Label:     "Set SSH ClientAliveCountMax",
		Actions: []Action{fileEdit("/etc/ssh/sshd_config", "Set ClientAliveCountMax", func(ctx Context) error {
			return exec.Command("sh", "-c", `grep -q '^ClientAliveCountMax' /etc/ssh/sshd_config && sed -i 's/^ClientAliveCountMax.*/ClientAliveCountMax 2/' /etc/ssh/sshd_config || echo 'ClientAliveCountMax 2' >> /etc/ssh/sshd_config`).Run()
		})},
	})
	r.Register(&Fix{
		FindingID: "lynis.AUTH-9328",
		Label:     "Restrict SSH users",
		Actions: []Action{fileEdit("/etc/ssh/sshd_config", "Add AllowUsers", func(ctx Context) error {
			return exec.Command("sh", "-c", `grep -q '^AllowUsers' /etc/ssh/sshd_config || echo 'AllowUsers root' >> /etc/ssh/sshd_config`).Run()
		})},
	})
	r.Register(&Fix{
		FindingID: "lynis.SSH-7408",
		Label:     "Harden SSH configuration",
		Actions: []Action{fileEdit("/etc/ssh/sshd_config", "Disable SSH compression", func(ctx Context) error {
			return exec.Command("sh", "-c", `grep -q '^Compression' /etc/ssh/sshd_config && sed -i 's/^Compression.*/Compression no/' /etc/ssh/sshd_config || echo 'Compression no' >> /etc/ssh/sshd_config`).Run()
		})},
	})

	// Auto (exec) — File permissions
	r.Register(&Fix{
		FindingID: "lynis.FILE-7524",
		Label:     "Fix /etc/issue permissions",
		Actions:   []Action{execCmd("chmod 644 /etc/issue")},
	})

	// Auto (exec/sysctl) — Network & Kernel hardening
	r.Register(&Fix{
		FindingID: "lynis.NETW-3200",
		Label:     "Harden network stack",
		Actions: []Action{
			sysctlApply("net.ipv4.tcp_syncookies", "1"),
			sysctlApply("net.ipv4.conf.all.rp_filter", "1"),
		},
	})
}

var dangerousPaths = []string{"/etc/shadow", "/etc/sudoers", "/etc/sudoers.d", "/etc/pam.d", "/etc/ssh/sshd_config"}

func sanitizePath(raw string) string {
	clean := filepath.Clean(raw)
	for _, dp := range dangerousPaths {
		if clean == dp {
			return ""
		}
	}
	if !strings.HasPrefix(clean, "/") {
		return ""
	}
	return clean
}

func sanitizeUser(raw string) string {
	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_', r == '-':
		default:
			return ""
		}
	}
	return raw
}

func sanitizePort(raw string) string {
	s := strings.TrimSuffix(raw, "/tcp")
	s = strings.TrimSuffix(s, "/udp")
	if s == "" {
		return ""
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return s
}
