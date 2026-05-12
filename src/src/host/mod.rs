use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub mod defensive;
pub mod docker;
pub mod filesystem;
mod fim;
pub mod firewall;
pub mod kernel;
pub mod mac;
pub mod ssh;
pub mod updates;

pub use defensive::collect_host_runtime_info;

use crate::domain::{Axis, Finding, HostRuntimeInfo, RemediationKind, Scope, Severity, Source};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostContext {
    pub root: PathBuf,
}

impl Default for HostContext {
    fn default() -> Self {
        Self {
            root: PathBuf::from("/"),
        }
    }
}

#[derive(Debug, Default)]
pub struct HostScanner;

impl HostScanner {
    pub fn scan(&self, context: &HostContext) -> Vec<Finding> {
        let runtime = defensive::collect_host_runtime_info(context);
        self.scan_with_runtime(context, &runtime)
    }

    pub fn scan_with_runtime(
        &self,
        context: &HostContext,
        runtime: &HostRuntimeInfo,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        findings.extend(ssh::scan_ssh_hardening(context));
        findings.extend(docker::scan_docker_host_exposure(context));
        findings.extend(docker::scan_docker_daemon_hardening(context));
        findings.extend(firewall::scan_firewall_hardening(context));
        findings.extend(updates::scan_package_update_hardening(context));
        findings.extend(kernel::scan_kernel_hardening(context));
        findings.extend(kernel::scan_secure_boot(context));
        findings.extend(kernel::scan_user_namespace_settings(context));
        findings.extend(filesystem::scan_mount_flags(context));
        findings.extend(filesystem::scan_proc_hidepid(context));
        findings.extend(mac::scan_mac_frameworks(context));
        findings.extend(filesystem::scan_systemd_hardening(context));
        findings.extend(filesystem::scan_grub_hardening(context));
        findings.extend(filesystem::scan_shadow_hardening(context));
        findings.extend(filesystem::scan_tmp_hardening(context));
        findings.extend(fim::scan_fim(context));
        findings.extend(defensive::scan_defensive_controls(context, runtime));
        findings
    }
}

pub(crate) fn host_finding(
    id: &str,
    severity: Severity,
    subject: &Path,
    text: HostFindingText,
    evidence: BTreeMap<String, String>,
    remediation: RemediationKind,
) -> Finding {
    Finding {
        id: id.to_owned(),
        axis: Axis::HostHardening,
        severity,
        scope: Scope::Host,
        source: Source::NativeHost,
        subject: subject.display().to_string(),
        related_service: None,
        title: text.title,
        description: text.description,
        why_risky: text.why_risky,
        how_to_fix: text.how_to_fix,
        evidence,
        remediation,
    }
}

pub(crate) struct HostFindingText {
    pub(crate) title: String,
    pub(crate) description: String,
    pub(crate) why_risky: String,
    pub(crate) how_to_fix: String,
}

pub(crate) fn resolve_existing_path(root: &Path, relative: &str) -> Option<PathBuf> {
    let path = root.join(relative);
    path.exists().then_some(path)
}

pub(crate) fn try_command(command: &[&str]) -> Option<String> {
    let (program, args) = command.split_first()?;
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    (!stdout.is_empty()).then_some(stdout)
}

pub(crate) fn is_live_root(root: &Path) -> bool {
    root.canonicalize()
        .map(|path| path == Path::new("/"))
        .unwrap_or(false)
}

pub(crate) fn format_permissions(mode: u32) -> String {
    format!("0o{:03o}", mode)
}

pub(crate) fn read_sysctl(context: &HostContext, relative: &str) -> Option<String> {
    let path = context.root.join(relative);
    let text = std::fs::read_to_string(&path).ok()?;
    let trimmed = text.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

pub(crate) fn strip_ini_comments(line: &str) -> &str {
    let trimmed = line.trim();
    if trimmed.starts_with('#') || trimmed.starts_with(';') {
        return "";
    }

    let hash_index = line.find('#');
    let semicolon_index = line.find(" ;").map(|index| index + 1);
    let comment_index = match (hash_index, semicolon_index) {
        (Some(hash), Some(semicolon)) => Some(hash.min(semicolon)),
        (Some(hash), None) => Some(hash),
        (None, Some(semicolon)) => Some(semicolon),
        (None, None) => None,
    };

    line[..comment_index.unwrap_or(line.len())].trim()
}

pub(crate) fn parse_ini_section(line: &str) -> Option<String> {
    let trimmed = line.trim();
    trimmed
        .strip_prefix('[')?
        .strip_suffix(']')
        .map(str::trim)
        .filter(|section| !section.is_empty())
        .map(str::to_owned)
}

pub(crate) fn parse_ini_key_value(line: &str) -> Option<(&str, &str)> {
    let (key, value) = line.split_once('=')?;
    Some((key.trim(), value.trim()))
}

pub(crate) fn parse_ini_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

pub(crate) fn strip_apt_comments(line: &str) -> &str {
    let trimmed = line.trim();
    if trimmed.starts_with('#') || trimmed.starts_with("//") {
        return "";
    }

    let hash_index = line.find('#');
    let slash_index = line.find("//");
    let comment_index = match (hash_index, slash_index) {
        (Some(hash), Some(slash)) => Some(hash.min(slash)),
        (Some(hash), None) => Some(hash),
        (None, Some(slash)) => Some(slash),
        (None, None) => None,
    };

    line[..comment_index.unwrap_or(line.len())].trim()
}

pub(crate) fn parse_apt_periodic_bool(text: &str, key: &str) -> Option<bool> {
    for raw_line in text.lines() {
        let line = strip_apt_comments(raw_line);
        if line.is_empty() || !line.contains(key) {
            continue;
        }

        let (_, value) = line.split_once(key)?;
        let value = value
            .trim()
            .trim_start_matches('=')
            .trim()
            .trim_end_matches(';')
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .trim();

        if let Some(enabled) = parse_ini_bool(value) {
            return Some(enabled);
        }
    }

    None
}

pub(crate) fn parse_ini_bool_in_section(
    text: &str,
    target_section: &str,
    target_key: &str,
) -> Option<bool> {
    let mut in_section = false;
    for raw_line in text.lines() {
        let line = strip_ini_comments(raw_line);
        if line.is_empty() {
            continue;
        }
        if let Some(section) = parse_ini_section(line) {
            in_section = section.eq_ignore_ascii_case(target_section);
            continue;
        }
        if !in_section {
            continue;
        }
        let Some((key, value)) = parse_ini_key_value(line) else {
            continue;
        };
        if key.eq_ignore_ascii_case(target_key) {
            return parse_ini_bool(value);
        }
    }
    None
}

pub(crate) fn parse_proc_mounts(text: &str) -> BTreeMap<String, Vec<String>> {
    let mut mounts = BTreeMap::new();

    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let mount_point = parts[1].to_owned();
        let options: Vec<String> = parts[3].split(',').map(String::from).collect();
        mounts.insert(mount_point, options);
    }

    mounts
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    pub(crate) fn temp_host_root(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should move forward")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "hostveil-host-{name}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("temp root should be created");
        path
    }

    pub(crate) fn write_file(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("parent should be created");
        }
        fs::write(path, content).expect("file should be written");
    }

    #[test]
    fn host_scanner_detects_insecure_ssh_and_docker_settings() {
        let root = temp_host_root("insecure");
        write_file(
            &root.join(ssh::SSH_CONFIG_PATH),
            concat!(
                "PermitRootLogin yes\n",
                "PasswordAuthentication yes\n",
                "PermitEmptyPasswords yes\n",
                "PubkeyAuthentication no\n",
                "PermitUserEnvironment yes\n"
            ),
        );
        write_file(
            &root.join(docker::DOCKER_DAEMON_CONFIG_PATH),
            r#"{"hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2375"], "tlsverify": false, "iptables": false}"#,
        );
        write_file(&root.join(docker::DOCKER_SOCKET_PATH), "socket");
        fs::set_permissions(
            root.join(docker::DOCKER_SOCKET_PATH),
            fs::Permissions::from_mode(0o666),
        )
        .expect("permissions should be set");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "host.ssh_root_login_enabled",
                "host.ssh_password_auth_enabled",
                "host.ssh_empty_passwords_enabled",
                "host.ssh_pubkey_auth_disabled",
                "host.ssh_user_environment_enabled",
                "host.ssh_listens_on_all_interfaces",
                "host.docker_socket_world_writable",
                "host.docker_daemon_tcp_public",
                "host.docker_daemon_tcp_no_tlsverify",
                "host.docker_daemon_iptables_disabled",
                "host.docker_userns_remap_missing",
                "host.docker_live_restore_disabled",
                "host.docker_log_driver_missing",
                "host.docker_default_ulimits_missing",
                "host.no_firewall_detected",
                "host.kernel.module_signing_not_enforced",
                "host.mac_framework_missing",
                "host.fim_missing",
                "host.defensive_controls_missing",
            ]
        );
        assert!(findings.iter().all(|finding| finding.scope == Scope::Host));
        assert!(
            findings
                .iter()
                .all(|finding| finding.source == Source::NativeHost)
        );

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_detects_insecure_sysctl_settings() {
        let root = temp_host_root("sysctl-insecure");
        write_file(&root.join("proc/sys/kernel/randomize_va_space"), "0\n");
        write_file(&root.join("proc/sys/net/ipv4/tcp_syncookies"), "0\n");
        write_file(
            &root.join("proc/sys/net/ipv4/icmp_echo_ignore_broadcasts"),
            "0\n",
        );
        write_file(&root.join("proc/sys/net/ipv4/ip_forward"), "1\n");
        write_file(
            &root.join("proc/sys/kernel/unprivileged_userns_clone"),
            "1\n",
        );
        write_file(&root.join("proc/sys/user/max_user_namespaces"), "1000\n");
        write_file(&root.join("etc/hostname"), "sysctl-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "host.no_firewall_detected",
                "host.kernel.aslr_disabled",
                "host.kernel.syn_cookies_disabled",
                "host.kernel.broadcast_ping_allowed",
                "host.kernel.ip_forward_enabled",
                "host.kernel.module_signing_not_enforced",
                "host.kernel.unprivileged_userns_clone_enabled",
                "host.kernel.max_user_namespaces_enabled",
                "host.mac_framework_missing",
                "host.fim_missing",
                "host.defensive_controls_missing",
            ]
        );

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_skips_hardened_sysctl_snapshot() {
        let root = temp_host_root("sysctl-hardened");
        write_file(&root.join("proc/sys/kernel/randomize_va_space"), "2\n");
        write_file(&root.join("proc/sys/net/ipv4/tcp_syncookies"), "1\n");
        write_file(
            &root.join("proc/sys/net/ipv4/icmp_echo_ignore_broadcasts"),
            "1\n",
        );
        write_file(&root.join("proc/sys/net/ipv4/ip_forward"), "0\n");
        write_file(
            &root.join("proc/sys/kernel/unprivileged_userns_clone"),
            "0\n",
        );
        write_file(&root.join("proc/sys/user/max_user_namespaces"), "0\n");
        write_file(&root.join("etc/ufw/ufw.conf"), "ENABLED=yes\n");
        write_file(
            &root.join("etc/fail2ban/jail.local"),
            "[sshd]\nenabled = true\n",
        );
        write_file(
            &root.join("etc/systemd/system/multi-user.target.wants/fail2ban.service"),
            "enabled\n",
        );
        write_file(
            &root.join("sys/kernel/security/apparmor/profiles"),
            concat!(
                "/usr/sbin/dnsmasq (enforce)\n",
                "/usr/bin/dockerd (enforce)\n",
                "/usr/sbin/nginx (enforce)\n",
                "/usr/sbin/sshd (enforce)\n",
            ),
        );
        write_file(
            &root.join("sys/module/module/parameters/sig_enforce"),
            "Y\n",
        );
        write_file(&root.join("usr/bin/aide"), "");
        write_file(&root.join("var/lib/aide/aide.db"), "");
        write_file(&root.join("etc/hostname"), "hardened\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(findings.is_empty());

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_detects_secure_boot_disabled() {
        let root = temp_host_root("secure-boot-disabled");
        let sb_path =
            root.join("sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c");
        fs::create_dir_all(sb_path.parent().unwrap()).expect("parent should be created");
        fs::write(&sb_path, [0x00, 0x00, 0x00, 0x00, 0x00]).expect("file should be written");
        write_file(&root.join("etc/hostname"), "sb-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert_eq!(
            findings.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(),
            vec![
                "host.no_firewall_detected",
                "host.kernel.module_signing_not_enforced",
                "host.secure_boot_disabled",
                "host.mac_framework_missing",
                "host.fim_missing",
                "host.defensive_controls_missing",
            ]
        );

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_skips_secure_boot_when_enabled() {
        let root = temp_host_root("secure-boot-enabled");
        let sb_path =
            root.join("sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c");
        fs::create_dir_all(sb_path.parent().unwrap()).expect("parent should be created");
        fs::write(&sb_path, [0x00, 0x00, 0x00, 0x00, 0x01]).expect("file should be written");
        write_file(&root.join("etc/hostname"), "sb-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert_eq!(
            findings.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(),
            vec![
                "host.no_firewall_detected",
                "host.kernel.module_signing_not_enforced",
                "host.mac_framework_missing",
                "host.fim_missing",
                "host.defensive_controls_missing",
            ]
        );

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_skips_hardened_snapshot() {
        let root = temp_host_root("hardened");
        write_file(
            &root.join(ssh::SSH_CONFIG_PATH),
            concat!(
                "PermitRootLogin no\n",
                "PasswordAuthentication no\n",
                "PermitEmptyPasswords no\n",
                "PubkeyAuthentication yes\n",
                "PermitUserEnvironment no\n",
                "ListenAddress 127.0.0.1\n"
            ),
        );
        write_file(
            &root.join(docker::DOCKER_DAEMON_CONFIG_PATH),
            r#"{"hosts": ["unix:///var/run/docker.sock", "tcp://127.0.0.1:2375"], "userns-remap": "default", "live-restore": true, "log-driver": "json-file", "log-opts": {"max-size": "10m", "max-file": "3"}, "default-ulimits": {"nofile": {"Name": "nofile", "Hard": 64000, "Soft": 64000}}}"#,
        );
        write_file(
            &root.join("etc/fail2ban/jail.local"),
            "[sshd]\nenabled = true\n",
        );
        write_file(
            &root.join("etc/systemd/system/multi-user.target.wants/fail2ban.service"),
            "enabled\n",
        );
        write_file(&root.join(docker::DOCKER_SOCKET_PATH), "socket");
        fs::set_permissions(
            root.join(docker::DOCKER_SOCKET_PATH),
            fs::Permissions::from_mode(0o660),
        )
        .expect("permissions should be set");
        write_file(&root.join("proc/sys/kernel/randomize_va_space"), "2\n");
        write_file(&root.join("proc/sys/net/ipv4/tcp_syncookies"), "1\n");
        write_file(
            &root.join("proc/sys/net/ipv4/icmp_echo_ignore_broadcasts"),
            "1\n",
        );
        write_file(&root.join("proc/sys/net/ipv4/ip_forward"), "0\n");
        write_file(
            &root.join("proc/sys/kernel/unprivileged_userns_clone"),
            "0\n",
        );
        write_file(&root.join("proc/sys/user/max_user_namespaces"), "0\n");
        write_file(&root.join("proc/sys/kernel/modules_disabled"), "1\n");
        write_file(
            &root.join("sys/module/module/parameters/sig_enforce"),
            "Y\n",
        );
        write_file(
            &root.join("sys/kernel/security/apparmor/profiles"),
            concat!(
                "/usr/sbin/dnsmasq (enforce)\n",
                "/usr/bin/dockerd (enforce)\n",
                "/usr/sbin/nginx (enforce)\n",
                "/usr/sbin/sshd (enforce)\n",
            ),
        );
        write_file(&root.join("usr/bin/aide"), "");
        write_file(&root.join("var/lib/aide/aide.db"), "");
        write_file(
            &root.join("boot/grub/grub.cfg"),
            "set superusers=\"admin\"\npassword_pbkdf2 admin grub.pbkdf2...\n",
        );
        write_file(
            &root.join("etc/shadow"),
            "root:$6$rounds=5000$salt$hash:0:0:root:/root:/bin/bash\n",
        );
        fs::set_permissions(root.join("etc/shadow"), fs::Permissions::from_mode(0o640))
            .expect("permissions should be set");
        write_file(
            &root.join("proc/mounts"),
            concat!(
                "proc /proc proc rw,relatime,hidepid=2 0 0\n",
                "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime 0 0\n",
                "ext4 / ext4 rw,relatime 0 0\n",
            ),
        );
        write_file(&root.join("etc/ufw/ufw.conf"), "ENABLED=yes\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(findings.is_empty());

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_warns_when_no_firewall() {
        let root = temp_host_root("no-firewall");
        write_file(&root.join("etc/hostname"), "no-fw\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.no_firewall_detected")
        );

        fs::remove_dir_all(root).expect("temp root should be removed");
    }
}
