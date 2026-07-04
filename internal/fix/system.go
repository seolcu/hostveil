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
// re-registered to avoid false-positive "fixable" findings.
//
// A Review fix has multiple actions representing INDEPENDENT alternatives the
// user picks between — NOT sequential stages. Never bundle N settings into 1
// Review action. See AGENTS.md "Review = alternatives, not stages" for the
// design rule.
//
// A fix reporting success=true MUST have made the expected system change.
// Shell scripts end with `set -e` (not `set +e; exit 0`) so that install
// failures propagate. Service-start steps (which legitimately may fail in
// containers without an init system) are best-effort with `|| true`.
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

	// ── BANN — Banners ────────────────────────────────────────────────
	r.Register(&Fix{
		FindingID: "lynis.BANN-7126",
		Label:     "Add legal banner to /etc/issue",
		Actions: []Action{{
			Type:     ActionEdit,
			Label:    "Add banner to /etc/issue",
			FilePath: "/etc/issue",
			Apply:    fileAppendIfMissing("/etc/issue", "Unauthorized access prohibited"),
		}},
	})

	// ── FILE — File permissions ───────────────────────────────────────
	r.Register(&Fix{
		FindingID: "lynis.FILE-7524",
		Label:     "Restrict /etc/issue permissions",
		Actions:   []Action{execCmd("chmod 644 /etc/issue")},
	})

	// ── SSH — Broad SSH hardening (Lynis reports many sub-concerns under SSH-7408) ──
	// 5 INDEPENDENT options, user picks one. Each modifies a different sshd
	// directive; none depend on the others. Class() auto-detects Review
	// from len(Actions) > 1, so no explicit Kind is needed.
	r.Register(&Fix{
		FindingID: "lynis.SSH-7408",
		Label:     "Harden SSH configuration",
		Actions: []Action{
			{
				Type:     ActionEdit,
				Label:    "Disable SSH compression",
				FilePath: "/etc/ssh/sshd_config",
				Warning:  "Disabling SSH compression may affect bandwidth for some workloads.",
				Apply:    sshdSetOption("Compression", "no"),
			},
			{
				Type:     ActionEdit,
				Label:    "Set SSH MaxAuthTries to 3",
				FilePath: "/etc/ssh/sshd_config",
				Warning:  "Lowering MaxAuthTries may affect brute-force tolerance.",
				Apply:    sshdSetOption("MaxAuthTries", "3"),
			},
			{
				Type:     ActionEdit,
				Label:    "Disable SSH TCPKeepAlive",
				FilePath: "/etc/ssh/sshd_config",
				Warning:  "Disabling TCPKeepAlive may cause stale sessions to linger longer.",
				Apply:    sshdSetOption("TCPKeepAlive", "no"),
			},
			{
				Type:     ActionEdit,
				Label:    "Disable SSH agent forwarding",
				FilePath: "/etc/ssh/sshd_config",
				Warning:  "Disabling agent forwarding may break workflows that rely on it.",
				Apply:    sshdSetOption("AllowAgentForwarding", "no"),
			},
			{
				Type:     ActionEdit,
				Label:    "Reduce MaxSessions to 2",
				FilePath: "/etc/ssh/sshd_config",
				Warning:  "Lowering MaxSessions may break multiplexing workflows.",
				Apply:    sshdSetOption("MaxSessions", "2"),
			},
		},
	})

	// ── AUTH — Password aging (Lynis AUTH-9286) ──────────────────────
	// 2 INDEPENDENT options. Either can be set without the other.
	// Class() auto-detects Review from len(Actions) > 1.
	r.Register(&Fix{
		FindingID: "lynis.AUTH-9286",
		Label:     "Configure password aging in /etc/login.defs",
		Actions: []Action{
			{
				Type:     ActionEdit,
				Label:    "Set PASS_MIN_DAYS to 1",
				FilePath: "/etc/login.defs",
				Warning:  "Setting minimum password age may prevent users from changing compromised passwords quickly.",
				Apply:    loginDefsSet("PASS_MIN_DAYS", "1"),
			},
			{
				Type:     ActionEdit,
				Label:    "Set PASS_MAX_DAYS to 365",
				FilePath: "/etc/login.defs",
				Warning:  "Forcing password rotation may disrupt user workflows. Adjust to your policy.",
				Apply:    loginDefsSet("PASS_MAX_DAYS", "365"),
			},
		},
	})

	// ── AUTH — umask (Lynis AUTH-9328) ───────────────────────────────
	// Single action — Auto. The Warning inside the action surfaces the
	// "this changes default file permissions" concern.
	r.Register(&Fix{
		FindingID: "lynis.AUTH-9328",
		Label:     "Set default umask to 027",
		Actions: []Action{{
			Type:     ActionEdit,
			Label:    "Set umask 027 in /etc/profile",
			FilePath: "/etc/profile",
			Warning:  "Tightening umask changes default file permissions for new files site-wide.",
			Apply:    fileAppendIfMissing("/etc/profile", "umask 027"),
		}},
	})

	// ── KRNL — Core dump (Lynis KRNL-5820) ───────────────────────────
	// Single action — Auto. The Warning surfaces "no post-mortem" concern.
	r.Register(&Fix{
		FindingID: "lynis.KRNL-5820",
		Label:     "Disable core dumps for all users",
		Actions: []Action{{
			Type:     ActionEdit,
			Label:    "Add * hard core 0 to /etc/security/limits.conf",
			FilePath: "/etc/security/limits.conf",
			Warning:  "Disabling core dumps makes post-mortem debugging impossible. Only disable if your environment does not require crash analysis.",
			Apply:    fileAppendIfMissing("/etc/security/limits.conf", "* hard core 0"),
		}},
	})

	// ── KRNL — sysctl hardening (Lynis KRNL-6000) ───────────────────
	// 6 INDEPENDENT options. User picks which sysctls to apply. e.g. an
	// operator of a router may want syncookies but NOT accept_source_route=0.
	// Class() auto-detects Review from len(Actions) > 1, no explicit Kind.
	r.Register(&Fix{
		FindingID: "lynis.KRNL-6000",
		Label:     "Kernel sysctl hardening",
		Actions: []Action{
			sysctlApplyAction("Set net.ipv4.conf.all.accept_source_route=0", "net.ipv4.conf.all.accept_source_route", "0"),
			sysctlApplyAction("Set net.ipv4.conf.all.send_redirects=0", "net.ipv4.conf.all.send_redirects", "0"),
			sysctlApplyAction("Set net.ipv4.tcp_syncookies=1", "net.ipv4.tcp_syncookies", "1"),
			sysctlApplyAction("Set net.ipv4.conf.all.rp_filter=1", "net.ipv4.conf.all.rp_filter", "1"),
			sysctlApplyAction("Set net.ipv4.icmp_echo_ignore_broadcasts=1", "net.ipv4.icmp_echo_ignore_broadcasts", "1"),
			sysctlApplyAction("Set net.ipv4.icmp_ignore_bogus_error_responses=1", "net.ipv4.icmp_ignore_bogus_error_responses", "1"),
		},
	})

	// ── LOGG — Syslog daemon (Lynis LOGG-2130) ───────────────────────
	// Single install action — Auto. The Warning dialog surfaces the
	// "service may not start in containers" concern.
	r.Register(&Fix{
		FindingID: "lynis.LOGG-2130",
		Label:     "Install and enable a syslog daemon (rsyslog)",
		Actions: []Action{{
			Type:    ActionExec,
			Label:   "Install and enable rsyslog",
			Warning: "Installing rsyslog requires internet access and a working init system. In containers without an init system, the package will be installed but the service may not start.",
			Apply: func(ctx Context) error {
				return runInstallAndStart("rsyslog", "rsyslog", "rsyslog", "rsyslog")
			},
		}},
	})

	// ── ACCT — sysstat (Lynis ACCT-9626) ────────────────────────────
	r.Register(&Fix{
		FindingID: "lynis.ACCT-9626",
		Label:     "Install sysstat for performance monitoring",
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
	// Package name differs per distro: Debian/RHEL = "auditd", Alpine = "audit".
	// installPackage() handles the alias fallback automatically.
	r.Register(&Fix{
		FindingID: "lynis.ACCT-9628",
		Label:     "Install and enable auditd",
		Actions: []Action{{
			Type:    ActionExec,
			Label:   "Install auditd",
			Warning: "auditd requires kernel support and a working init system to start the daemon. On Alpine, the package is named 'audit' (handled internally).",
			Apply: func(ctx Context) error {
				return runInstallAndStart("auditd", "auditd", "auditd", "auditd")
			},
		}},
	})

	// ── NETW — uncommon network protocols (Lynis NETW-3200) ─────────
	r.Register(&Fix{
		FindingID: "lynis.NETW-3200",
		Label:     "Disable uncommon network protocols (dccp, sctp, rds, tipc)",
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
				if err := exec.Command("sh", "-c", fmt.Sprintf("mkdir -p /etc/modprobe.d && cat > %s <<'EOF'\n%sEOF\n", shellQuote(path), content)).Run(); err != nil {
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
		Actions: []Action{{
			Type:    ActionExec,
			Label:   "Install and enable chrony",
			Warning: "Installing chrony requires internet access. Configure your NTP sources (NTP_SERVERS) before relying on it.",
			Apply: func(ctx Context) error {
				// chrony package + chronyd service on Alpine, chrony on Debian/RHEL
				return runInstallAndStart("chrony", "chrony", "chrony", "chronyd")
			},
		}},
	})

	// ── Manual — concerns without an automated fix ──────────────────
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

	// ── Additional Lynis 3.1.6 reference IDs ─────────────────────────
	r.Register(&Fix{
		FindingID: "lynis.AUTH-9216",
		Label:     "Run grpck to verify group file consistency (grpck -r /etc/group). Fix any duplicate GIDs or orphaned entries reported. This is site-specific — review each warning before editing /etc/group.",
		Kind:      domain.RemediationManual,
		Actions:   nil,
	})

	r.Register(&Fix{
		FindingID: "lynis.AUTH-9230",
		Label:     "Increase password hashing rounds",
		Actions: []Action{{
			Type:     ActionEdit,
			Label:    "Set SHA_CRYPT_MIN_ROUNDS to 5000 in /etc/login.defs",
			FilePath: "/etc/login.defs",
			Warning:  "Higher rounds slow password hashing and may affect login performance on low-end hardware.",
			Apply:    loginDefsSet("SHA_CRYPT_MIN_ROUNDS", "5000"),
		}},
	})

	r.Register(&Fix{
		FindingID: "lynis.FILE-6310",
		Label:     "/home should be on a separate partition. This requires disk layout changes during provisioning or migration — back up data, create a new partition or volume, copy /home, update /etc/fstab, and reboot.",
		Kind:      domain.RemediationManual,
		Actions:   nil,
	})

	r.Register(&Fix{
		FindingID: "lynis.FINT-4350",
		Label:     "Install a file integrity tool (AIDE or Tripwire)",
		Actions: []Action{{
			Type:    ActionExec,
			Label:   "Install AIDE",
			Warning: "AIDE requires periodic baseline updates after system changes. Initial database creation can take several minutes.",
			Apply: func(ctx Context) error {
				return installPackage("aide")
			},
		}},
	})

	r.Register(&Fix{
		FindingID: "lynis.HRDN-7230",
		Label:     "Install a malware scanner (ClamAV or rkhunter)",
		Actions: []Action{{
			Type:    ActionExec,
			Label:   "Install ClamAV",
			Warning: "ClamAV requires regular signature updates (freshclam). Scanning large filesystems can be CPU-intensive.",
			Apply: func(ctx Context) error {
				return runInstallAndStart("clamav", "clamav-daemon", "clamav-update", "clamd")
			},
		}},
	})

	r.Register(&Fix{
		FindingID: "lynis.LOGG-2138",
		Label:     "Install and enable klogd for kernel logging",
		Actions: []Action{{
			Type:    ActionExec,
			Label:   "Install klogd",
			Warning: "klogd is legacy on many modern distros where the kernel logs directly to syslog/journald. Verify your distro still ships it before applying.",
			Apply: func(ctx Context) error {
				return runInstallAndStart("klogd", "klogd", "klogd", "klogd")
			},
		}},
	})

	r.Register(&Fix{
		FindingID: "lynis.NAME-4028",
		Label:     "Configure DNS properly in /etc/resolv.conf or via systemd-resolved/NetworkManager. Ensure at least one working nameserver is configured and that search domains match your network.",
		Kind:      domain.RemediationManual,
		Actions:   nil,
	})

	r.Register(&Fix{
		FindingID: "lynis.PKGS-7398",
		Label:     "Enable automatic security updates. On Debian/Ubuntu install unattended-upgrades; on RHEL/Fedora enable dnf-automatic; on Alpine review apk upgrade scheduling via cron.",
		Kind:      domain.RemediationManual,
		Actions:   nil,
	})

	r.Register(&Fix{
		FindingID: "lynis.TOOL-5002",
		Label:     "Review installed automation tools (Ansible, Puppet, Chef, Salt). Remove unused agents and restrict credentials for tools that remain. Ensure automation runs over SSH keys, not passwords.",
		Kind:      domain.RemediationManual,
		Actions:   nil,
	})

	r.Register(&Fix{
		FindingID: "lynis.USB-1000",
		Label:     "Disable USB storage to prevent unauthorized data exfiltration",
		Actions: []Action{{
			Type:    ActionExec,
			Label:   "Blacklist usb-storage module",
			Warning: "Disabling USB storage prevents using USB flash drives and some external devices. Review whether your environment needs USB storage before applying.",
			Apply: func(ctx Context) error {
				content := `# Disabled by hostveil
install usb-storage /bin/true
blacklist usb-storage
`
				path := "/etc/modprobe.d/hv-disable-usb-storage.conf"
				return exec.Command("sh", "-c", fmt.Sprintf("mkdir -p /etc/modprobe.d && cat > %s <<'EOF'\n%sEOF\n", shellQuote(path), content)).Run()
			},
		}},
	})
}

// ── Helpers (extracted for unit-testability) ──────────────────────────

// sshdSetOption returns an Apply that sets `key value` in /etc/ssh/sshd_config.
// If the key is already present (possibly commented out), the line is updated.
// Otherwise the option is appended.
func sshdSetOption(key, value string) func(Context) error {
	return func(ctx Context) error {
		return sshdSetOptionAt("/etc/ssh/sshd_config", key, value)
	}
}

// sshdSetOptionAt is the path-parameterized core of sshdSetOption, exposed
// for unit tests so they can run against temp files.
func sshdSetOptionAt(path, key, value string) error {
	script := fmt.Sprintf(
		"if grep -qE '^#?\\s*%s\\b' %s; then sed -i -E 's/^#?\\s*%s\\b.*/%s %s/' %s; else echo '%s %s' >> %s; fi",
		key, shellQuote(path), key, key, value, shellQuote(path), key, value, shellQuote(path))
	return exec.Command("sh", "-c", script).Run()
}

// loginDefsSet sets KEY value in /etc/login.defs (replace existing or append).
func loginDefsSet(key, value string) func(Context) error {
	return func(ctx Context) error {
		return loginDefsSetAt("/etc/login.defs", key, value)
	}
}

// loginDefsSetAt is the path-parameterized core of loginDefsSet.
func loginDefsSetAt(path, key, value string) error {
	script := fmt.Sprintf(
		"if grep -qE '^#?\\s*%s\\b' %s; then sed -i -E 's/^#?\\s*%s\\b.*/%s %s/' %s; else echo '%s %s' >> %s; fi",
		key, shellQuote(path), key, key, value, shellQuote(path), key, value, shellQuote(path))
	return exec.Command("sh", "-c", script).Run()
}

// fileAppendIfMissing returns an Apply that appends `line` to `path` if a
// line with the same key prefix is not already present. Idempotent.
func fileAppendIfMissing(path, line string) func(Context) error {
	return func(ctx Context) error {
		return fileAppendIfMissingAt(path, line)
	}
}

// fileAppendIfMissingAt is the testable core of fileAppendIfMissing.
func fileAppendIfMissingAt(path, line string) error {
	// Use a substring of the line as marker (e.g. first 32 bytes) to
	// determine if it's already there. `len` returns bytes, not runes;
	// `grep -F` also operates on bytes, so the marker is consistent
	// with grep's view of the file. Callers that need rune-correct
	// truncation should pre-truncate `line` themselves.
	marker := line
	if len(marker) > 32 {
		marker = marker[:32]
	}
	script := fmt.Sprintf(
		"if ! grep -qF %s %s 2>/dev/null; then echo %s >> %s; fi",
		shellQuote(marker), shellQuote(path), shellQuote(line), shellQuote(path))
	return exec.Command("sh", "-c", script).Run()
}

// shellQuote wraps a string in single quotes for safe shell interpolation.
// Used to build script arguments for sh -c.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// sysctlApplyAction returns an Action that sets a kernel sysctl both at
// runtime (sysctl -w) and persistently in /etc/sysctl.conf. Returns the
// Action so it can be placed in an Actions slice.
func sysctlApplyAction(label, param, value string) Action {
	return Action{
		Type:    ActionExec,
		Label:   label,
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

// runInstallAndStart installs a package and best-effort starts its service
// across apt/apk/dnf. `set -e` ensures install failures propagate. The
// service-start step is `|| true`-guarded because it legitimately fails in
// environments without an init system (containers, chroots, etc.).
//
// `pkg` is the package name on all distros (same as the function name).
// `serviceApt` and `serviceDnf` are the systemd unit names on Debian/RHEL.
// `serviceAlpine` is the OpenRC service name on Alpine (often "chronyd" vs "chrony").
//
// All four arguments are passed through `shellQuote` so a future caller
// passing user-controlled values (e.g. a finding's evidence field) can't
// inject shell metacharacters. Current call sites pass hardcoded ASCII
// literals, but the helpers are now the public seam for new fixes.
func runInstallAndStart(pkg, serviceApt, serviceDnf, serviceAlpine string) error {
	script := fmt.Sprintf(`set -e
if command -v apt-get >/dev/null 2>&1; then
    apt-get install -y %s
    if [ -d /run/systemd/system ]; then
        systemctl enable --now %s 2>/dev/null || true
    else
        service %s start 2>/dev/null || true
    fi
elif command -v apk >/dev/null 2>&1; then
    apk add %s 2>/dev/null || apk add %s
    if command -v rc-update >/dev/null 2>&1; then
        rc-update add %s default 2>/dev/null || true
    fi
    if command -v rc-service >/dev/null 2>&1; then
        rc-service %s start 2>/dev/null || true
    fi
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y %s
    if [ -d /run/systemd/system ]; then
        systemctl enable --now %s 2>/dev/null || true
    else
        service %s start 2>/dev/null || true
    fi
else
    echo "No supported package manager (apt/apk/dnf) found" >&2
    exit 1
fi
`, shellQuote(pkg), shellQuote(serviceApt), shellQuote(serviceApt),
		shellQuote(pkg), shellQuote(alpineAlias(pkg)),
		shellQuote(serviceAlpine), shellQuote(serviceAlpine),
		shellQuote(pkg), shellQuote(serviceDnf), shellQuote(serviceDnf))
	return exec.Command("sh", "-c", script).Run()
}

// alpineAlias returns the Alpine package name for the given generic name,
// or the generic name itself if no alias is known. The lookup is needed
// because some packages have different names across distros (e.g. auditd
// on Debian is 'audit' on Alpine).
func alpineAlias(pkg string) string {
	if alias, ok := alpinePackageAliases[pkg]; ok {
		return alias
	}
	return pkg
}

// alpinePackageAliases maps "generic" package names (used in fix code) to
// the equivalent Alpine package name. When `apk add <pkg>` fails, the
// installer tries the alias before reporting an error.
var alpinePackageAliases = map[string]string{
	"auditd": "audit",
}

// installPackage installs the named package using the detected package
// manager. On Alpine, if the direct name fails, the alpinePackageAliases
// map is consulted. Returns an error if no supported package manager is
// found or the install ultimately fails.
//
// This helper is used by the simpler "install only, no service start" fixes
// (sysstat, acct). Fixes that need a service start use runInstallAndStart().
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
		if err == nil {
			return nil
		}
		// Direct install failed — try the Alpine alias if one is known.
		if alias := alpineAlias(pkg); alias != pkg {
			out2, err2 := exec.Command("apk", "add", alias).CombinedOutput()
			if err2 == nil {
				return nil
			}
			return fmt.Errorf("apk add %s (and alias %s) failed: %s; %s", pkg, alias, string(out), string(out2))
		}
		return fmt.Errorf("apk add %s failed: %s", pkg, string(out))
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
