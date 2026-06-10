package fix

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/seolcu/hostveil/internal/domain"
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

	// Review — SSH
	r.Register(&Fix{
		FindingID: "lynis.AUTH-9286",
		Label:     "Disable SSH password authentication",
		Kind:      domain.RemediationReview,
		Actions: []Action{{
			Type:     ActionEdit,
			Label:    "Disable SSH password authentication",
			FilePath: "/etc/ssh/sshd_config",
			Warning:  "Disabling password auth may lock out users who do not have SSH keys configured. Ensure key-based auth works first.",
			Apply: func(ctx Context) error {
				return exec.Command("sed", "-i", `s/^#\?PasswordAuthentication.*/PasswordAuthentication no/`, "/etc/ssh/sshd_config").Run()
			},
		}},
	})
	r.Register(&Fix{
		FindingID: "lynis.AUTH-9308",
		Label:     "Restrict root SSH login",
		Kind:      domain.RemediationReview,
		Actions: []Action{{
			Type:     ActionEdit,
			Label:    "Restrict root SSH login",
			FilePath: "/etc/ssh/sshd_config",
			Warning:  "Changing root SSH login policy may prevent administrative access. Verify an alternative account has sudo access.",
			Apply: func(ctx Context) error {
				return exec.Command("sed", "-i", `s/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/`, "/etc/ssh/sshd_config").Run()
			},
		}},
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

	// Review — Kernel
	r.Register(&Fix{
		FindingID: "lynis.KRNL-5780",
		Label:     "Disable IP forwarding",
		Kind:      domain.RemediationReview,
		Actions: []Action{{
			Type:    ActionExec,
			Label:   "Set sysctl net.ipv4.ip_forward=0",
			Command: []string{"sysctl", "-w", "net.ipv4.ip_forward=0"},
			Warning: "Disabling IP forwarding will break any routing, NAT, or VPN functionality. Skip if this host acts as a router.",
			Apply: func(ctx Context) error {
				if err := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=0").Run(); err != nil {
					return err
				}
				entry := "net.ipv4.ip_forward=0"
				param := "net.ipv4.ip_forward"
				if exec.Command("sh", "-c", fmt.Sprintf("grep -q '^%s=' /etc/sysctl.conf", param)).Run() != nil {
					return exec.Command("sh", "-c", fmt.Sprintf("echo '%s' >> /etc/sysctl.conf", entry)).Run()
				}
				return exec.Command("sh", "-c", fmt.Sprintf("sed -i 's/^#*\\s*%s\\s*=.*/%s/' /etc/sysctl.conf", param, entry)).Run()
			},
		}},
	})
	r.Register(&Fix{
		FindingID: "lynis.KRNL-5820",
		Label:     "Disable ICMP redirect",
		Kind:      domain.RemediationReview,
		Actions: []Action{{
			Type:    ActionExec,
			Label:   "Set sysctl net.ipv4.conf.all.accept_redirects=0",
			Command: []string{"sysctl", "-w", "net.ipv4.conf.all.accept_redirects=0"},
			Warning: "Disabling ICMP redirects may affect network path optimization. Review for your network topology.",
			Apply: func(ctx Context) error {
				if err := exec.Command("sysctl", "-w", "net.ipv4.conf.all.accept_redirects=0").Run(); err != nil {
					return err
				}
				entry := "net.ipv4.conf.all.accept_redirects=0"
				param := "net.ipv4.conf.all.accept_redirects"
				if exec.Command("sh", "-c", fmt.Sprintf("grep -q '^%s=' /etc/sysctl.conf", param)).Run() != nil {
					return exec.Command("sh", "-c", fmt.Sprintf("echo '%s' >> /etc/sysctl.conf", entry)).Run()
				}
				return exec.Command("sh", "-c", fmt.Sprintf("sed -i 's/^#*\\s*%s\\s*=.*/%s/' /etc/sysctl.conf", param, entry)).Run()
			},
		}},
	})
	r.Register(&Fix{
		FindingID: "lynis.NETW-2705",
		Label:     "Harden network stack",
		Actions: []Action{
			{
				Type:    ActionExec,
				Label:   "Run: sysctl -w net.ipv4.tcp_syncookies=1",
				Command: []string{"sysctl", "-w", "net.ipv4.tcp_syncookies=1"},
				Warning: "Enabling syncookies may affect high-throughput TCP servers. Enabling rp_filter may drop legitimate packets in asymmetric routing setups.",
				Apply: func(ctx Context) error {
					return exec.Command("sysctl", "-w", "net.ipv4.tcp_syncookies=1").Run()
				},
			},
			execCmd("sysctl -w net.ipv4.conf.all.rp_filter=1"),
		},
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

	// Review — Accounts
	r.Register(&Fix{
		FindingID: "lynis.ACCT-9626",
		Label:     "Set password aging",
		Kind:      domain.RemediationReview,
		Actions: []Action{{
			Type:    ActionExec,
			Label:   "Set password aging to 90 days",
			Command: []string{"chage", "-M", "90"},
			Warning: "Setting password aging to 90 days may disrupt users who do not expect forced password changes. Notify users before applying.",
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
			{
				Type:    ActionExec,
				Label:   "Run: ufw --force enable",
				Command: []string{"ufw", "--force", "enable"},
				Warning: "Enabling firewall with default-deny policies will block all incoming connections including SSH. Ensure SSH (port 22) or your custom port is explicitly allowed first.",
				Apply: func(ctx Context) error {
					return exec.Command("ufw", "--force", "enable").Run()
				},
			},
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
				Warning: "Blocking ports may disrupt services. The default port is 22 (SSH) — verify the port is correct before blocking.",
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
				Type:    ActionExec,
				Label:   "Block port with iptables",
				Warning: "Adding iptables DROP rules may persist only until reboot unless saved.",
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

	// Manual — LDAP
	r.Register(&Fix{
		FindingID: "lynis.AUTH-9265",
		Label:     "LDAP authentication requires site-specific configuration. Install libnss-ldap/pam-ldap (Debian), nss-pam-ldapd (RHEL), or nss-pam-ldapd (Alpine) and run pam-auth-update. Consult your LDAP administrator for server details.",
		Kind:      domain.RemediationManual,
		Actions:   nil,
	})

	// Manual — SELinux/AppArmor
	r.Register(&Fix{
		FindingID: "lynis.HRMN-6114",
		Label:     "Enabling SELinux or AppArmor requires kernel support and may need a reboot. Install selinux-policy-default/apparmor (Debian), selinux-policy (RHEL), or apparmor (Alpine). Set enforcing mode after verifying no denials in permissive mode.",
		Kind:      domain.RemediationManual,
		Actions:   nil,
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
		Kind:      domain.RemediationReview,
		Actions: []Action{{
			Type:    ActionExec,
			Label:   "Set sysctl net.ipv4.conf.all.rp_filter=1",
			Command: []string{"sysctl", "-w", "net.ipv4.conf.all.rp_filter=1"},
			Warning: "Enabling rp_filter (strict mode) may drop legitimate packets in asymmetric routing setups. Consider mode 2 (loose) for multi-homed hosts.",
			Apply: func(ctx Context) error {
				if err := exec.Command("sysctl", "-w", "net.ipv4.conf.all.rp_filter=1").Run(); err != nil {
					return err
				}
				entry := "net.ipv4.conf.all.rp_filter=1"
				param := "net.ipv4.conf.all.rp_filter"
				if exec.Command("sh", "-c", fmt.Sprintf("grep -q '^%s=' /etc/sysctl.conf", param)).Run() != nil {
					return exec.Command("sh", "-c", fmt.Sprintf("echo '%s' >> /etc/sysctl.conf", entry)).Run()
				}
				return exec.Command("sh", "-c", fmt.Sprintf("sed -i 's/^#*\\s*%s\\s*=.*/%s/' /etc/sysctl.conf", param, entry)).Run()
			},
		}},
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
		Kind:      domain.RemediationReview,
		Actions: []Action{{
			Type:    ActionExec,
			Label:   "Set sysctl net.ipv4.tcp_timestamps=0",
			Command: []string{"sysctl", "-w", "net.ipv4.tcp_timestamps=0"},
			Warning: "Disabling TCP timestamps may affect TCP performance tuning or applications that rely on them. Review before applying.",
			Apply: func(ctx Context) error {
				if err := exec.Command("sysctl", "-w", "net.ipv4.tcp_timestamps=0").Run(); err != nil {
					return err
				}
				entry := "net.ipv4.tcp_timestamps=0"
				param := "net.ipv4.tcp_timestamps"
				if exec.Command("sh", "-c", fmt.Sprintf("grep -q '^%s=' /etc/sysctl.conf", param)).Run() != nil {
					return exec.Command("sh", "-c", fmt.Sprintf("echo '%s' >> /etc/sysctl.conf", entry)).Run()
				}
				return exec.Command("sh", "-c", fmt.Sprintf("sed -i 's/^#*\\s*%s\\s*=.*/%s/' /etc/sysctl.conf", param, entry)).Run()
			},
		}},
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

	// Review — SSH
	r.Register(&Fix{
		FindingID: "lynis.AUTH-9208",
		Label:     "Disable SSH protocol 1",
		Kind:      domain.RemediationReview,
		Actions: []Action{{
			Type:     ActionEdit,
			Label:    "Set SSH Protocol 2",
			FilePath: "/etc/ssh/sshd_config",
			Warning:  "Modifying SSH protocol version may affect legacy clients. Verify all clients support Protocol 2.",
			Apply: func(ctx Context) error {
				return exec.Command("sh", "-c", `grep -q '^Protocol' /etc/ssh/sshd_config && sed -i 's/^Protocol.*/Protocol 2/' /etc/ssh/sshd_config || echo 'Protocol 2' >> /etc/ssh/sshd_config`).Run()
			},
		}},
	})
	r.Register(&Fix{
		FindingID: "lynis.AUTH-9222",
		Label:     "Set password minimum days",
		Kind:      domain.RemediationReview,
		Actions: []Action{{
			Type:     ActionEdit,
			Label:    "Set PASS_MIN_DAYS",
			FilePath: "/etc/login.defs",
			Warning:  "Setting minimum password age may prevent users from changing compromised passwords quickly. Review your policy.",
			Apply: func(ctx Context) error {
				return exec.Command("sh", "-c", `grep -q '^PASS_MIN_DAYS' /etc/login.defs && sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs || echo 'PASS_MIN_DAYS 1' >> /etc/login.defs`).Run()
			},
		}},
	})
	r.Register(&Fix{
		FindingID: "lynis.AUTH-9223",
		Label:     "Set password maximum days",
		Kind:      domain.RemediationReview,
		Actions: []Action{{
			Type:     ActionEdit,
			Label:    "Set PASS_MAX_DAYS",
			FilePath: "/etc/login.defs",
			Warning:  "Setting maximum password age will force periodic password changes. Ensure users are aware of the policy.",
			Apply: func(ctx Context) error {
				return exec.Command("sh", "-c", `grep -q '^PASS_MAX_DAYS' /etc/login.defs && sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs || echo 'PASS_MAX_DAYS 90' >> /etc/login.defs`).Run()
			},
		}},
	})
	r.Register(&Fix{
		FindingID: "lynis.AUTH-9262",
		Label:     "Configure sudo timestamp timeout",
		Kind:      domain.RemediationReview,
		Actions: []Action{{
			Type:     ActionEdit,
			Label:    "Set sudo timestamp timeout",
			FilePath: "/etc/sudoers.d/hv-timeout",
			Warning:  "Modifying sudoers.d configuration may affect sudo behavior. Verify /etc/sudoers.d/hv-timeout does not conflict with existing sudo rules.",
			Apply: func(ctx Context) error {
				return exec.Command("sh", "-c", `echo 'Defaults timestamp_timeout=5' > /etc/sudoers.d/hv-timeout && chmod 440 /etc/sudoers.d/hv-timeout`).Run()
			},
		}},
	})

	// Review — Boot security
	r.Register(&Fix{
		FindingID: "lynis.BOOT-5120",
		Label:     "Set GRUB bootloader password",
		Kind:      domain.RemediationReview,
		Actions: []Action{{
			Type:    ActionExec,
			Label:   "Set GRUB password to 'password' (grub2-set-password, change after boot)",
			Warning: "The default password is 'password'. Change it immediately after boot. If you lose GRUB access, you will need boot media to recover.",
			Apply: func(ctx Context) error {
				return exec.Command("sh", "-c", `echo -e "password\npassword" | grub2-set-password 2>/dev/null`).Run()
			},
		}, {
			Type:    ActionExec,
			Label:   "Set GRUB password to 'password' (grub-set-password, change after boot)",
			Warning: "The default password is 'password'. Change it immediately after boot. If you lose GRUB access, you will need boot media to recover.",
			Apply: func(ctx Context) error {
				return exec.Command("sh", "-c", `echo -e "password\npassword" | grub-set-password 2>/dev/null`).Run()
			},
		}},
	})

	// Review — Logging
	r.Register(&Fix{
		FindingID: "lynis.LOGG-2100",
		Label:     "Enable syslog-ng or rsyslog",
		Kind:      domain.RemediationReview,
		Actions: []Action{{
			Type:    ActionExec,
			Label:   "Install and enable rsyslog",
			Warning: "Installing and enabling rsyslog requires internet access and may conflict with existing logging daemons. Review before applying.",
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

	// Review — Time sync
	r.Register(&Fix{
		FindingID: "lynis.TIME-3106",
		Label:     "Configure NTP/Chrony",
		Kind:      domain.RemediationReview,
		Actions: []Action{{
			Type:    ActionExec,
			Label:   "Install and enable chrony",
			Warning: "Installing chrony requires internet access and NTP server configuration. Ensure time sources are reachable.",
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

	// Review — SSH
	r.Register(&Fix{
		FindingID: "lynis.AUTH-9216",
		Label:     "Set SSH MaxAuthTries",
		Kind:      domain.RemediationReview,
		Actions: []Action{{
			Type:     ActionEdit,
			Label:    "Set SSH MaxAuthTries",
			FilePath: "/etc/ssh/sshd_config",
			Warning:  "Changing SSH authentication limits may affect automated tools or monitoring. Review before applying.",
			Apply: func(ctx Context) error {
				return exec.Command("sh", "-c", `grep -q '^MaxAuthTries' /etc/ssh/sshd_config && sed -i 's/^MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config || echo 'MaxAuthTries 3' >> /etc/ssh/sshd_config`).Run()
			},
		}},
	})
	r.Register(&Fix{
		FindingID: "lynis.AUTH-9229",
		Label:     "Set SSH ClientAliveInterval",
		Kind:      domain.RemediationReview,
		Actions: []Action{{
			Type:     ActionEdit,
			Label:    "Set SSH ClientAliveInterval",
			FilePath: "/etc/ssh/sshd_config",
			Warning:  "Changing SSH keepalive may disconnect long-running sessions. Adjust interval to your environment.",
			Apply: func(ctx Context) error {
				return exec.Command("sh", "-c", `grep -q '^ClientAliveInterval' /etc/ssh/sshd_config && sed -i 's/^ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config || echo 'ClientAliveInterval 300' >> /etc/ssh/sshd_config`).Run()
			},
		}},
	})
	r.Register(&Fix{
		FindingID: "lynis.AUTH-9230",
		Label:     "Set SSH ClientAliveCountMax",
		Kind:      domain.RemediationReview,
		Actions: []Action{{
			Type:     ActionEdit,
			Label:    "Set SSH ClientAliveCountMax",
			FilePath: "/etc/ssh/sshd_config",
			Warning:  "Changing SSH keepalive count may disconnect sessions. Adjust to your environment.",
			Apply: func(ctx Context) error {
				return exec.Command("sh", "-c", `grep -q '^ClientAliveCountMax' /etc/ssh/sshd_config && sed -i 's/^ClientAliveCountMax.*/ClientAliveCountMax 2/' /etc/ssh/sshd_config || echo 'ClientAliveCountMax 2' >> /etc/ssh/sshd_config`).Run()
			},
		}},
	})
	r.Register(&Fix{
		FindingID: "lynis.AUTH-9328",
		Label:     "Restrict SSH users with AllowUsers in /etc/ssh/sshd_config. Choose specific users for your environment — do NOT use a placeholder like 'root' alone. Example: AllowUsers admin operator. Restart sshd after editing.",
		Kind:      domain.RemediationManual,
		Actions:   nil,
	})
	r.Register(&Fix{
		FindingID: "lynis.SSH-7408",
		Label:     "Harden SSH configuration",
		Kind:      domain.RemediationReview,
		Actions: []Action{{
			Type:     ActionEdit,
			Label:    "Disable SSH compression",
			FilePath: "/etc/ssh/sshd_config",
			Warning:  "Disabling SSH compression may affect bandwidth for some workloads. Review for your use case.",
			Apply: func(ctx Context) error {
				return exec.Command("sh", "-c", `grep -q '^Compression' /etc/ssh/sshd_config && sed -i 's/^Compression.*/Compression no/' /etc/ssh/sshd_config || echo 'Compression no' >> /etc/ssh/sshd_config`).Run()
			},
		}},
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
			{
				Type:    ActionExec,
				Label:   "Set sysctl net.ipv4.tcp_syncookies=1",
				Command: []string{"sysctl", "-w", "net.ipv4.tcp_syncookies=1"},
				Warning: "Enabling syncookies may affect high-throughput TCP servers. Enabling rp_filter may drop legitimate packets in asymmetric routing setups.",
				Apply: func(ctx Context) error {
					if err := exec.Command("sysctl", "-w", "net.ipv4.tcp_syncookies=1").Run(); err != nil {
						return err
					}
					entry := "net.ipv4.tcp_syncookies=1"
					param := "net.ipv4.tcp_syncookies"
					if exec.Command("sh", "-c", fmt.Sprintf("grep -q '^%s=' /etc/sysctl.conf", param)).Run() != nil {
						return exec.Command("sh", "-c", fmt.Sprintf("echo '%s' >> /etc/sysctl.conf", entry)).Run()
					}
					return exec.Command("sh", "-c", fmt.Sprintf("sed -i 's/^#*\\s*%s\\s*=.*/%s/' /etc/sysctl.conf", param, entry)).Run()
				},
			},
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
