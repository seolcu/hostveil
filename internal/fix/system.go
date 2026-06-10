package fix

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/seolcu/hostveil/internal/domain"
)

// registerSystemFixes wires up fixes for host-hardening findings reported by
// Lynis 3.1.6. Each registered ID MUST match a real test ID in the current
// Lynis report; see system_validate_test.go for the runtime check.
//
// IDs that no longer appear in current Lynis reports are intentionally not
// re-registered to avoid false-positive "fixable" findings. The hard-coded
// fix logic is preserved in dormant helpers (systemDormant) so it can be
// re-attached if Lynis reintroduces the test in a future release.
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

	// ── BANN — Banners ────────────────────────────────────────────────
	r.Register(&Fix{
		FindingID: "lynis.BANN-7126",
		Label:     "Add legal banner to /etc/issue",
		Actions: []Action{fileEdit("/etc/issue", "Add banner to /etc/issue", func(ctx Context) error {
			return exec.Command("sh", "-c", `grep -q "Unauthorized access prohibited" /etc/issue 2>/dev/null || echo "Unauthorized access prohibited" >> /etc/issue`).Run()
		})},
	})

	// ── FILE — File permissions ───────────────────────────────────────
	r.Register(&Fix{
		FindingID: "lynis.FILE-7524",
		Label:     "Restrict /etc/issue permissions",
		Actions:   []Action{execCmd("chmod 644 /etc/issue")},
	})

	// ── SSH — Broad SSH hardening (Lynis reports many sub-concerns under SSH-7408) ──
	r.Register(&Fix{
		FindingID: "lynis.SSH-7408",
		Label:     "Harden SSH configuration",
		Kind:      domain.RemediationReview,
		Actions: []Action{
			{
				Type:     ActionEdit,
				Label:    "Disable SSH compression",
				FilePath: "/etc/ssh/sshd_config",
				Warning:  "Disabling SSH compression may affect bandwidth for some workloads.",
				Apply: func(ctx Context) error {
					return exec.Command("sh", "-c", `grep -q '^Compression' /etc/ssh/sshd_config && sed -i 's/^Compression.*/Compression no/' /etc/ssh/sshd_config || echo 'Compression no' >> /etc/ssh/sshd_config`).Run()
				},
			},
			{
				Type:     ActionEdit,
				Label:    "Set SSH MaxAuthTries to 3",
				FilePath: "/etc/ssh/sshd_config",
				Warning:  "Lowering MaxAuthTries may affect brute-force tolerance.",
				Apply: func(ctx Context) error {
					return exec.Command("sh", "-c", `grep -q '^MaxAuthTries' /etc/ssh/sshd_config && sed -i 's/^MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config || echo 'MaxAuthTries 3' >> /etc/ssh/sshd_config`).Run()
				},
			},
			{
				Type:     ActionEdit,
				Label:    "Disable SSH TCPKeepAlive",
				FilePath: "/etc/ssh/sshd_config",
				Warning:  "Disabling TCPKeepAlive may cause stale sessions to linger longer.",
				Apply: func(ctx Context) error {
					return exec.Command("sh", "-c", `grep -q '^TCPKeepAlive' /etc/ssh/sshd_config && sed -i 's/^TCPKeepAlive.*/TCPKeepAlive no/' /etc/ssh/sshd_config || echo 'TCPKeepAlive no' >> /etc/ssh/sshd_config`).Run()
				},
			},
			{
				Type:     ActionEdit,
				Label:    "Disable SSH agent forwarding",
				FilePath: "/etc/ssh/sshd_config",
				Warning:  "Disabling agent forwarding may break workflows that rely on it.",
				Apply: func(ctx Context) error {
					return exec.Command("sh", "-c", `grep -q '^AllowAgentForwarding' /etc/ssh/sshd_config && sed -i 's/^AllowAgentForwarding.*/AllowAgentForwarding no/' /etc/ssh/sshd_config || echo 'AllowAgentForwarding no' >> /etc/ssh/sshd_config`).Run()
				},
			},
			{
				Type:     ActionEdit,
				Label:    "Reduce MaxSessions to 2",
				FilePath: "/etc/ssh/sshd_config",
				Warning:  "Lowering MaxSessions may break multiplexing workflows.",
				Apply: func(ctx Context) error {
					return exec.Command("sh", "-c", `grep -q '^MaxSessions' /etc/ssh/sshd_config && sed -i 's/^MaxSessions.*/MaxSessions 2/' /etc/ssh/sshd_config || echo 'MaxSessions 2' >> /etc/ssh/sshd_config`).Run()
				},
			},
		},
	})

	// ── AUTH — Password aging (Lynis AUTH-9286) ──────────────────────
	r.Register(&Fix{
		FindingID: "lynis.AUTH-9286",
		Label:     "Configure password aging in /etc/login.defs",
		Kind:      domain.RemediationReview,
		Actions: []Action{
			{
				Type:     ActionEdit,
				Label:    "Set PASS_MIN_DAYS to 1",
				FilePath: "/etc/login.defs",
				Warning:  "Setting minimum password age may prevent users from changing compromised passwords quickly.",
				Apply: func(ctx Context) error {
					return exec.Command("sh", "-c", `grep -q '^PASS_MIN_DAYS' /etc/login.defs && sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs || echo 'PASS_MIN_DAYS 1' >> /etc/login.defs`).Run()
				},
			},
			{
				Type:     ActionEdit,
				Label:    "Set PASS_MAX_DAYS to 365",
				FilePath: "/etc/login.defs",
				Warning:  "Forcing password rotation may disrupt user workflows. Adjust to your policy.",
				Apply: func(ctx Context) error {
					return exec.Command("sh", "-c", `grep -q '^PASS_MAX_DAYS' /etc/login.defs && sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 365/' /etc/login.defs || echo 'PASS_MAX_DAYS 365' >> /etc/login.defs`).Run()
				},
			},
		},
	})

	// ── AUTH — umask (Lynis AUTH-9328) ───────────────────────────────
	r.Register(&Fix{
		FindingID: "lynis.AUTH-9328",
		Label:     "Set default umask to 027",
		Kind:      domain.RemediationReview,
		Actions: []Action{
			{
				Type:     ActionEdit,
				Label:    "Set umask 027 in /etc/profile",
				FilePath: "/etc/profile",
				Warning:  "Tightening umask changes default file permissions for new files site-wide.",
				Apply: func(ctx Context) error {
					return exec.Command("sh", "-c", `grep -q '^umask 027' /etc/profile || echo 'umask 027' >> /etc/profile`).Run()
				},
			},
		},
	})

	// ── KRNL — Core dump (Lynis KRNL-5820) ───────────────────────────
	r.Register(&Fix{
		FindingID: "lynis.KRNL-5820",
		Label:     "Disable core dumps for all users",
		Kind:      domain.RemediationReview,
		Actions: []Action{{
			Type:     ActionEdit,
			Label:    "Add * hard core 0 to /etc/security/limits.conf",
			FilePath: "/etc/security/limits.conf",
			Warning:  "Disabling core dumps makes post-mortem debugging impossible. Only disable if your environment does not require crash analysis.",
			Apply: func(ctx Context) error {
				return exec.Command("sh", "-c", `grep -q '^\* hard core 0' /etc/security/limits.conf || echo '* hard core 0' >> /etc/security/limits.conf`).Run()
			},
		}},
	})

	// ── KRNL — sysctl catch-all (Lynis KRNL-6000) ───────────────────
	// The current report has only KRNL-6000 as the sysctl-related finding;
	// the previously-used individual IDs (KRNL-5830, KRNL-5840, KRNL-5860,
	// KRNL-5870, KRNL-5880, KRNL-5890, KRNL-5930) no longer match. We
	// bundle the recommended sysctl profile into a single shell-driven
	// action so the user gets the full hardening set in one click.
	r.Register(&Fix{
		FindingID: "lynis.KRNL-6000",
		Label:     "Apply recommended kernel hardening sysctls",
		Kind:      domain.RemediationReview,
		Actions: []Action{{
			Type:    ActionExec,
			Label:   "Apply kernel hardening sysctls (source_route=0, send_redirects=0, syncookies=1, rp_filter=1, echo_ignore=1, bogus_icmp=1)",
			Warning: "These settings may affect routing, NAT, or high-throughput TCP workloads. Review for your network topology before applying.",
			Apply: func(ctx Context) error {
				entries := []struct{ param, value string }{
					{"net.ipv4.conf.all.accept_source_route", "0"},
					{"net.ipv4.conf.all.send_redirects", "0"},
					{"net.ipv4.tcp_syncookies", "1"},
					{"net.ipv4.conf.all.rp_filter", "1"},
					{"net.ipv4.icmp_echo_ignore_broadcasts", "1"},
					{"net.ipv4.icmp_ignore_bogus_error_responses", "1"},
				}
				for _, e := range entries {
					if err := exec.Command("sysctl", "-w", fmt.Sprintf("%s=%s", e.param, e.value)).Run(); err != nil {
						return err
					}
				}
				// Persist to /etc/sysctl.conf: one pass, append all entries
				// that are not already present, then update existing ones.
				for _, e := range entries {
					param, value := e.param, e.value
					entry := fmt.Sprintf("%s=%s", param, value)
					existsErr := exec.Command("sh", "-c", fmt.Sprintf("grep -q '^%s=' /etc/sysctl.conf", param)).Run()
					if existsErr != nil {
						if err := exec.Command("sh", "-c", fmt.Sprintf("echo '%s' >> /etc/sysctl.conf", entry)).Run(); err != nil {
							return err
						}
					} else {
						if err := exec.Command("sh", "-c", fmt.Sprintf("sed -i 's/^#*\\s*%s\\s*=.*/%s/' /etc/sysctl.conf", param, entry)).Run(); err != nil {
							return err
						}
					}
				}
				return nil
			},
		}},
	})

	// ── LOGG — Syslog daemon (Lynis LOGG-2130) ───────────────────────
	// Robust installer: detects init system, installs rsyslog, best-effort
	// start (no error if init system is missing, e.g. in containers).
	r.Register(&Fix{
		FindingID: "lynis.LOGG-2130",
		Label:     "Install and enable a syslog daemon (rsyslog)",
		Kind:      domain.RemediationReview,
		Actions: []Action{{
			Type:    ActionExec,
			Label:   "Install and enable rsyslog",
			Warning: "Installing rsyslog requires internet access and a working init system. In containers without an init system, the package will be installed but the service may not start.",
			Apply: func(ctx Context) error {
				script := `set +e
if command -v apt-get >/dev/null 2>&1; then
    apt-get install -y rsyslog
    if [ -d /run/systemd/system ]; then
        systemctl enable --now rsyslog 2>/dev/null
    else
        service rsyslog start 2>/dev/null
    fi
elif command -v apk >/dev/null 2>&1; then
    apk add rsyslog
    if command -v rc-update >/dev/null 2>&1; then
        rc-update add rsyslog default 2>/dev/null
    fi
    if command -v rc-service >/dev/null 2>&1; then
        rc-service rsyslog start 2>/dev/null
    fi
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y rsyslog
    if [ -d /run/systemd/system ]; then
        systemctl enable --now rsyslog 2>/dev/null
    else
        service rsyslog start 2>/dev/null
    fi
else
    echo "No supported package manager (apt/apk/dnf) found" >&2
    exit 1
fi
exit 0
`
				return exec.Command("sh", "-c", script).Run()
			},
		}},
	})

	// ── ACCT — sysstat (Lynis ACCT-9626) ────────────────────────────
	r.Register(&Fix{
		FindingID: "lynis.ACCT-9626",
		Label:     "Install sysstat for performance monitoring",
		Kind:      domain.RemediationReview,
		Actions: []Action{{
			Type:    ActionExec,
			Label:   "Install sysstat",
			Warning: "Requires internet access and a cron daemon for scheduled data collection.",
			Apply: func(ctx Context) error {
				return installPackage("sysstat")
			},
		}},
	})

	// ── ACCT — process accounting (Lynis ACCT-9622) ──────────────────
	r.Register(&Fix{
		FindingID: "lynis.ACCT-9622",
		Label:     "Enable process accounting",
		Kind:      domain.RemediationReview,
		Actions: []Action{{
			Type:    ActionExec,
			Label:   "Install process accounting tools",
			Warning: "Process accounting records every command run by every user; this can generate large log volumes and has privacy implications.",
			Apply: func(ctx Context) error {
				return installPackage("acct")
			},
		}},
	})

	// ── ACCT — auditd (Lynis ACCT-9628) ─────────────────────────────
	r.Register(&Fix{
		FindingID: "lynis.ACCT-9628",
		Label:     "Install and enable auditd",
		Kind:      domain.RemediationReview,
		Actions: []Action{{
			Type:    ActionExec,
			Label:   "Install auditd",
			Warning: "auditd requires kernel support and a working init system to start the daemon.",
			Apply: func(ctx Context) error {
				script := `set +e
if command -v apt-get >/dev/null 2>&1; then
    apt-get install -y auditd
    if [ -d /run/systemd/system ]; then
        systemctl enable --now auditd 2>/dev/null
    else
        service auditd start 2>/dev/null
    fi
elif command -v apk >/dev/null 2>&1; then
    apk add auditd
    if command -v rc-update >/dev/null 2>&1; then
        rc-update add auditd default 2>/dev/null
    fi
    if command -v rc-service >/dev/null 2>&1; then
        rc-service auditd start 2>/dev/null
    fi
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y auditd
    if [ -d /run/systemd/system ]; then
        systemctl enable --now auditd 2>/dev/null
    else
        service auditd start 2>/dev/null
    fi
else
    echo "No supported package manager (apt/apk/dnf) found" >&2
    exit 1
fi
exit 0
`
				return exec.Command("sh", "-c", script).Run()
			},
		}},
	})

	// ── NETW — uncommon network protocols (Lynis NETW-3200) ─────────
	r.Register(&Fix{
		FindingID: "lynis.NETW-3200",
		Label:     "Disable uncommon network protocols (dccp, sctp, rds, tipc)",
		Kind:      domain.RemediationReview,
		Actions: []Action{{
			Type:    ActionExec,
			Label:   "Blacklist dccp, sctp, rds, tipc in modprobe",
			Warning: "Disabling these protocols may break applications that rely on them. Review network requirements first.",
			Apply: func(ctx Context) error {
				content := `# Disabled by hostveil
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
`
				path := "/etc/modprobe.d/hv-disable-uncommon-protocols.conf"
				if err := exec.Command("sh", "-c", fmt.Sprintf("mkdir -p /etc/modprobe.d && cat > %s <<'EOF'\n%sEOF\n", path, content)).Run(); err != nil {
					return err
				}
				// Best-effort immediate removal of any currently loaded modules
				_ = exec.Command("sh", "-c", "modprobe -r dccp sctp rds tipc 2>/dev/null").Run()
				return nil
			},
		}},
	})

	// ── TIME — NTP (Lynis TIME-3104) ─────────────────────────────────
	r.Register(&Fix{
		FindingID: "lynis.TIME-3104",
		Label:     "Install and enable an NTP daemon (chrony)",
		Kind:      domain.RemediationReview,
		Actions: []Action{{
			Type:    ActionExec,
			Label:   "Install and enable chrony",
			Warning: "Installing chrony requires internet access. Configure your NTP sources (NTP_SERVERS) before relying on it.",
			Apply: func(ctx Context) error {
				script := `set +e
if command -v apt-get >/dev/null 2>&1; then
    apt-get install -y chrony
    if [ -d /run/systemd/system ]; then
        systemctl enable --now chrony 2>/dev/null
    else
        service chrony start 2>/dev/null
    fi
elif command -v apk >/dev/null 2>&1; then
    apk add chrony
    if command -v rc-update >/dev/null 2>&1; then
        rc-update add chronyd default 2>/dev/null
    fi
    if command -v rc-service >/dev/null 2>&1; then
        rc-service chronyd start 2>/dev/null
    fi
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y chrony
    if [ -d /run/systemd/system ]; then
        systemctl enable --now chronyd 2>/dev/null
    else
        service chronyd start 2>/dev/null
    fi
else
    echo "No supported package manager (apt/apk/dnf) found" >&2
    exit 1
fi
exit 0
`
				return exec.Command("sh", "-c", script).Run()
			},
		}},
	})

	// ── Manual — concerns without an automated fix ──────────────────
	// Each entry explains what the user must do manually. Surfaced via
	// RemediationManual so the UI shows guidance instead of an Apply button.

	r.Register(&Fix{
		FindingID: "lynis.AUTH-9262",
		Label:     "Install a PAM module for password strength testing (pam_cracklib on Debian/RHEL, libpam-passwdqc on Alpine). Configure /etc/pam.d/common-password to enforce strength requirements. Restart affected services after editing.",
		Kind:      domain.RemediationManual,
		Actions:   nil,
	})

	r.Register(&Fix{
		FindingID: "lynis.AUTH-9308",
		Label:     "Set a password for single-user (recovery) mode to prevent local physical attackers from gaining root. Boot to single-user mode and run 'passwd' for the root account. Consider also setting a GRUB password (BOOT-5120) for full protection.",
		Kind:      domain.RemediationManual,
		Actions:   nil,
	})

	r.Register(&Fix{
		FindingID: "lynis.FIRE-4590",
		Label:     "Configure a host firewall. On Debian/Ubuntu use ufw; on RHEL/Fedora use firewalld; on Alpine use iptables/nftables rules. Open only the ports your services need. After enabling, verify SSH access is preserved before closing the session.",
		Kind:      domain.RemediationManual,
		Actions:   nil,
	})

	r.Register(&Fix{
		FindingID: "lynis.AUTH-9265",
		Label:     "LDAP authentication requires site-specific configuration. Install libnss-ldap/pam-ldap (Debian), nss-pam-ldapd (RHEL), or nss-pam-ldapd (Alpine) and run pam-auth-update. Consult your LDAP administrator for server details.",
		Kind:      domain.RemediationManual,
		Actions:   nil,
	})

	r.Register(&Fix{
		FindingID: "lynis.HRMN-6114",
		Label:     "Enabling SELinux or AppArmor requires kernel support and may need a reboot. Install selinux-policy-default/apparmor (Debian), selinux-policy (RHEL), or apparmor (Alpine). Set enforcing mode after verifying no denials in permissive mode.",
		Kind:      domain.RemediationManual,
		Actions:   nil,
	})
}

// installPackage installs the named package using the detected package manager.
// Returns an error if no supported package manager is found or the install
// command fails. Network failures bubble up as-is.
func installPackage(pkg string) error {
	if _, err := exec.LookPath("apt-get"); err == nil {
		out, err := exec.Command("apt-get", "install", "-y", pkg).CombinedOutput()
		if err != nil {
			return fmt.Errorf("apt-get install %s failed: %s", pkg, string(out))
		}
		return nil
	}
	if _, err := exec.LookPath("apk"); err == nil {
		out, err := exec.Command("apk", "add", pkg).CombinedOutput()
		if err != nil {
			return fmt.Errorf("apk add %s failed: %s", pkg, string(out))
		}
		return nil
	}
	if _, err := exec.LookPath("dnf"); err == nil {
		out, err := exec.Command("dnf", "install", "-y", pkg).CombinedOutput()
		if err != nil {
			return fmt.Errorf("dnf install %s failed: %s", pkg, string(out))
		}
		return nil
	}
	return fmt.Errorf("no supported package manager (apt/apk/dnf) found")
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
