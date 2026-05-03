use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use glob::glob;
use serde_json::Value as JsonValue;

use crate::domain::{
    Axis, DefensiveControlStatus, Finding, HostRuntimeInfo, RemediationKind, Scope, Severity,
    Source,
};

const SSH_CONFIG_PATH: &str = "etc/ssh/sshd_config";
const WEAK_KEX_ALGORITHMS: [&str; 2] =
    ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"];
const WEAK_MAC_ALGORITHMS: [&str; 4] =
    ["hmac-md5", "hmac-md5-96", "hmac-sha1-96", "hmac-ripemd160"];
const WEAK_CIPHER_ALGORITHMS: [&str; 6] = [
    "arcfour",
    "arcfour128",
    "arcfour256",
    "blowfish-cbc",
    "3des-cbc",
    "cast128-cbc",
];
const DOCKER_DAEMON_CONFIG_PATH: &str = "etc/docker/daemon.json";
const DOCKER_SOCKET_PATH: &str = "var/run/docker.sock";
const UFW_CONFIG_PATH: &str = "etc/ufw/ufw.conf";
const UFW_DEFAULT_POLICY_PATH: &str = "etc/default/ufw";
const UFW_INSTALL_MARKERS: [&str; 3] = ["etc/ufw/ufw.conf", "usr/sbin/ufw", "usr/bin/ufw"];
const FIREWALLD_CONFIG_PATH: &str = "etc/firewalld/firewalld.conf";
const FIREWALLD_CMD_PATHS: [&str; 2] = ["usr/bin/firewall-cmd", "usr/sbin/firewall-cmd"];
const FIREWALLD_SERVICE_PATHS: [&str; 3] = [
    "usr/lib/systemd/system/firewalld.service",
    "lib/systemd/system/firewalld.service",
    "etc/systemd/system/firewalld.service",
];
const FIREWALLD_ENABLED_MARKERS: [&str; 2] = [
    "etc/systemd/system/multi-user.target.wants/firewalld.service",
    "etc/systemd/system/default.target.wants/firewalld.service",
];
const NFTABLES_CONF_PATH: &str = "etc/nftables.conf";
const NFT_PATHS: [&str; 2] = ["usr/sbin/nft", "sbin/nft"];
const APT_AUTO_UPGRADES_CONFIG_PATH: &str = "etc/apt/apt.conf.d/20auto-upgrades";
const APT_PERIODIC_UNATTENDED_UPGRADE_KEY: &str = "APT::Periodic::Unattended-Upgrade";
const APT_PERIODIC_UPDATE_PACKAGE_LISTS_KEY: &str = "APT::Periodic::Update-Package-Lists";
const DNF_AUTOMATIC_CONF_PATH: &str = "etc/dnf/automatic.conf";
const DNF_AUTOMATIC_TIMER_ENABLED: [&str; 2] = [
    "etc/systemd/system/multi-user.target.wants/dnf-automatic.timer",
    "etc/systemd/system/timers.target.wants/dnf-automatic.timer",
];
const YUM_CRON_CONF_PATH: &str = "etc/yum/yum-cron.conf";
const YUM_CRON_SERVICE_ENABLED: [&str; 2] = [
    "etc/systemd/system/multi-user.target.wants/yum-cron.service",
    "etc/systemd/system/default.target.wants/yum-cron.service",
];
const FAIL2BAN_INSTALL_MARKERS: [&str; 6] = [
    "etc/fail2ban",
    "usr/bin/fail2ban-client",
    "usr/bin/fail2ban-server",
    "usr/sbin/fail2ban-server",
    "lib/systemd/system/fail2ban.service",
    "usr/lib/systemd/system/fail2ban.service",
];
const FAIL2BAN_ENABLED_MARKERS: [&str; 2] = [
    "etc/systemd/system/multi-user.target.wants/fail2ban.service",
    "etc/systemd/system/default.target.wants/fail2ban.service",
];

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
        let runtime = collect_host_runtime_info(context);
        self.scan_with_runtime(context, &runtime)
    }

    pub fn scan_with_runtime(
        &self,
        context: &HostContext,
        runtime: &HostRuntimeInfo,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        findings.extend(scan_ssh_hardening(context));
        findings.extend(scan_docker_host_exposure(context));
        findings.extend(scan_docker_daemon_hardening(context));
        findings.extend(scan_firewall_hardening(context));
        findings.extend(scan_package_update_hardening(context));
        findings.extend(scan_kernel_hardening(context));
        findings.extend(scan_user_namespace_settings(context));
        findings.extend(scan_mount_flags(context));
        findings.extend(scan_proc_hidepid(context));
        findings.extend(scan_mac_frameworks(context));
        findings.extend(scan_systemd_hardening(context));
        findings.extend(scan_grub_hardening(context));
        findings.extend(scan_shadow_hardening(context));
        findings.extend(scan_tmp_hardening(context));
        findings.extend(scan_defensive_controls(context, runtime));
        findings
    }
}

pub fn collect_host_runtime_info(context: &HostContext) -> HostRuntimeInfo {
    let controls = collect_defensive_controls_snapshot(&context.root);

    HostRuntimeInfo {
        hostname: read_hostname(&context.root),
        docker_version: discover_docker_version(&context.root),
        uptime: read_uptime(&context.root),
        load_average: read_load_average(&context.root),
        fail2ban: controls.fail2ban_status,
        fail2ban_jails: controls.fail2ban_jails,
        fail2ban_banned_ips: controls.fail2ban_banned_ips,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct DefensiveControlsSnapshot {
    fail2ban_status: DefensiveControlStatus,
    fail2ban_jails: Option<usize>,
    fail2ban_banned_ips: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct Fail2BanLiveSummary {
    jails: Option<usize>,
    banned_ips: Option<usize>,
}

fn host_finding(
    id: &str,
    severity: Severity,
    subject: &Path,
    text: HostFindingText,
    evidence: BTreeMap<String, String>,
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
        remediation: RemediationKind::None,
    }
}

struct HostFindingText {
    title: String,
    description: String,
    why_risky: String,
    how_to_fix: String,
}

fn scan_ssh_hardening(context: &HostContext) -> Vec<Finding> {
    let Some(config_path) = resolve_existing_path(&context.root, SSH_CONFIG_PATH) else {
        return Vec::new();
    };

    let Ok(config_result) = parse_sshd_config(&context.root, &config_path) else {
        return Vec::new();
    };

    let settings = &config_result.settings;
    let mut findings = Vec::new();

    if let Some(setting) = settings.get("permitrootlogin")
        && setting.value != "no"
    {
        let subject_path = &setting.source;
        let value = setting.value.as_str();
        findings.push(host_finding(
            "host.ssh_root_login_enabled",
            Severity::High,
            subject_path,
            HostFindingText {
                title: t!("finding.host.ssh_root_login.title").into_owned(),
                description: t!(
                    "finding.host.ssh_root_login.description",
                    path = subject_path.display().to_string(),
                    value = value
                )
                .into_owned(),
                why_risky: t!("finding.host.ssh_root_login.why").into_owned(),
                how_to_fix: t!("finding.host.ssh_root_login.fix").into_owned(),
            },
            BTreeMap::from([
                (String::from("path"), subject_path.display().to_string()),
                (String::from("value"), value.to_owned()),
            ]),
        ));
    }

    if let Some(setting) = settings.get("passwordauthentication")
        && setting.value == "yes"
    {
        let subject_path = &setting.source;
        findings.push(host_finding(
            "host.ssh_password_auth_enabled",
            Severity::High,
            subject_path,
            HostFindingText {
                title: t!("finding.host.ssh_password_auth.title").into_owned(),
                description: t!(
                    "finding.host.ssh_password_auth.description",
                    path = subject_path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.ssh_password_auth.why").into_owned(),
                how_to_fix: t!("finding.host.ssh_password_auth.fix").into_owned(),
            },
            BTreeMap::from([(String::from("path"), subject_path.display().to_string())]),
        ));
    }

    if let Some(setting) = settings.get("permitemptypasswords")
        && setting.value == "yes"
    {
        let subject_path = &setting.source;
        findings.push(host_finding(
            "host.ssh_empty_passwords_enabled",
            Severity::Critical,
            subject_path,
            HostFindingText {
                title: t!("finding.host.ssh_empty_passwords.title").into_owned(),
                description: t!(
                    "finding.host.ssh_empty_passwords.description",
                    path = subject_path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.ssh_empty_passwords.why").into_owned(),
                how_to_fix: t!("finding.host.ssh_empty_passwords.fix").into_owned(),
            },
            BTreeMap::from([(String::from("path"), subject_path.display().to_string())]),
        ));
    }

    if let Some(setting) = settings.get("pubkeyauthentication")
        && setting.value == "no"
    {
        let subject_path = &setting.source;
        findings.push(host_finding(
            "host.ssh_pubkey_auth_disabled",
            Severity::Medium,
            subject_path,
            HostFindingText {
                title: t!("finding.host.ssh_pubkey_auth.title").into_owned(),
                description: t!(
                    "finding.host.ssh_pubkey_auth.description",
                    path = subject_path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.ssh_pubkey_auth.why").into_owned(),
                how_to_fix: t!("finding.host.ssh_pubkey_auth.fix").into_owned(),
            },
            BTreeMap::from([(String::from("path"), subject_path.display().to_string())]),
        ));
    }

    if let Some(setting) = settings.get("permituserenvironment")
        && setting.value == "yes"
    {
        let subject_path = &setting.source;
        findings.push(host_finding(
            "host.ssh_user_environment_enabled",
            Severity::Medium,
            subject_path,
            HostFindingText {
                title: t!("finding.host.ssh_user_environment.title").into_owned(),
                description: t!(
                    "finding.host.ssh_user_environment.description",
                    path = subject_path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.ssh_user_environment.why").into_owned(),
                how_to_fix: t!("finding.host.ssh_user_environment.fix").into_owned(),
            },
            BTreeMap::from([(String::from("path"), subject_path.display().to_string())]),
        ));
    }

    if let Some(setting) = settings.get("x11forwarding")
        && setting.value == "yes"
    {
        let subject_path = &setting.source;
        findings.push(host_finding(
            "host.ssh_x11_forwarding_enabled",
            Severity::Medium,
            subject_path,
            HostFindingText {
                title: t!("finding.host.ssh_x11_forwarding.title").into_owned(),
                description: t!(
                    "finding.host.ssh_x11_forwarding.description",
                    path = subject_path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.ssh_x11_forwarding.why").into_owned(),
                how_to_fix: t!("finding.host.ssh_x11_forwarding.fix").into_owned(),
            },
            BTreeMap::from([(String::from("path"), subject_path.display().to_string())]),
        ));
    }

    // ListenAddress — default is 0.0.0.0 (all interfaces). Flag if missing or
    // if any entry binds to a wildcard address.
    if !config_result.listen_addresses.is_empty() {
        if config_result
            .listen_addresses
            .iter()
            .any(|s| is_wildcard_listen_address(&s.value))
        {
            let subject_path = &config_result.listen_addresses[0].source;
            let values = config_result
                .listen_addresses
                .iter()
                .map(|s| s.value.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            findings.push(host_finding(
                "host.ssh_listens_on_all_interfaces",
                Severity::Medium,
                subject_path,
                HostFindingText {
                    title: t!("finding.host.ssh_listen_all.title").into_owned(),
                    description: t!(
                        "finding.host.ssh_listen_all.description",
                        path = subject_path.display().to_string(),
                        values = values
                    )
                    .into_owned(),
                    why_risky: t!("finding.host.ssh_listen_all.why").into_owned(),
                    how_to_fix: t!("finding.host.ssh_listen_all.fix").into_owned(),
                },
                BTreeMap::from([
                    (String::from("path"), subject_path.display().to_string()),
                    (String::from("values"), values),
                ]),
            ));
        }
    } else {
        let subject_path = &config_path;
        findings.push(host_finding(
            "host.ssh_listens_on_all_interfaces",
            Severity::Medium,
            subject_path,
            HostFindingText {
                title: t!("finding.host.ssh_listen_all.title").into_owned(),
                description: t!(
                    "finding.host.ssh_listen_all.description_default",
                    path = subject_path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.ssh_listen_all.why").into_owned(),
                how_to_fix: t!("finding.host.ssh_listen_all.fix").into_owned(),
            },
            BTreeMap::from([(String::from("path"), subject_path.display().to_string())]),
        ));
    }

    if let Some(setting) = settings.get("kexalgorithms") {
        let weak = find_weak_algorithms(&setting.value, &WEAK_KEX_ALGORITHMS);
        if !weak.is_empty() {
            let subject_path = &setting.source;
            findings.push(host_finding(
                "host.ssh_weak_kex",
                Severity::High,
                subject_path,
                HostFindingText {
                    title: t!("finding.host.ssh_weak_kex.title").into_owned(),
                    description: t!(
                        "finding.host.ssh_weak_kex.description",
                        path = subject_path.display().to_string(),
                        algorithms = weak.join(", ")
                    )
                    .into_owned(),
                    why_risky: t!("finding.host.ssh_weak_kex.why").into_owned(),
                    how_to_fix: t!("finding.host.ssh_weak_kex.fix").into_owned(),
                },
                BTreeMap::from([
                    (String::from("path"), subject_path.display().to_string()),
                    (String::from("algorithms"), weak.join(", ")),
                ]),
            ));
        }
    }

    if let Some(setting) = settings.get("macs") {
        let weak = find_weak_algorithms(&setting.value, &WEAK_MAC_ALGORITHMS);
        if !weak.is_empty() {
            let subject_path = &setting.source;
            findings.push(host_finding(
                "host.ssh_weak_macs",
                Severity::High,
                subject_path,
                HostFindingText {
                    title: t!("finding.host.ssh_weak_macs.title").into_owned(),
                    description: t!(
                        "finding.host.ssh_weak_macs.description",
                        path = subject_path.display().to_string(),
                        algorithms = weak.join(", ")
                    )
                    .into_owned(),
                    why_risky: t!("finding.host.ssh_weak_macs.why").into_owned(),
                    how_to_fix: t!("finding.host.ssh_weak_macs.fix").into_owned(),
                },
                BTreeMap::from([
                    (String::from("path"), subject_path.display().to_string()),
                    (String::from("algorithms"), weak.join(", ")),
                ]),
            ));
        }
    }

    if let Some(setting) = settings.get("ciphers") {
        let weak = find_weak_algorithms(&setting.value, &WEAK_CIPHER_ALGORITHMS);
        if !weak.is_empty() {
            let subject_path = &setting.source;
            findings.push(host_finding(
                "host.ssh_weak_ciphers",
                Severity::High,
                subject_path,
                HostFindingText {
                    title: t!("finding.host.ssh_weak_ciphers.title").into_owned(),
                    description: t!(
                        "finding.host.ssh_weak_ciphers.description",
                        path = subject_path.display().to_string(),
                        algorithms = weak.join(", ")
                    )
                    .into_owned(),
                    why_risky: t!("finding.host.ssh_weak_ciphers.why").into_owned(),
                    how_to_fix: t!("finding.host.ssh_weak_ciphers.fix").into_owned(),
                },
                BTreeMap::from([
                    (String::from("path"), subject_path.display().to_string()),
                    (String::from("algorithms"), weak.join(", ")),
                ]),
            ));
        }
    }

    findings
}

fn find_weak_algorithms(value: &str, weak_list: &[&str]) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|alg| {
            let lower = alg.to_ascii_lowercase();
            weak_list.contains(&lower.as_str())
        })
        .map(String::from)
        .collect()
}

fn is_wildcard_listen_address(value: &str) -> bool {
    value == "0.0.0.0" || value == "::" || value == "*"
}

fn scan_docker_host_exposure(context: &HostContext) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Some(socket_path) = resolve_existing_path(&context.root, DOCKER_SOCKET_PATH)
        && let Ok(metadata) = fs::metadata(&socket_path)
    {
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o002 != 0 {
            findings.push(host_finding(
                "host.docker_socket_world_writable",
                Severity::Critical,
                &socket_path,
                HostFindingText {
                    title: t!("finding.host.docker_socket_world_writable.title").into_owned(),
                    description: t!(
                        "finding.host.docker_socket_world_writable.description",
                        path = socket_path.display().to_string(),
                        mode = format_permissions(mode)
                    )
                    .into_owned(),
                    why_risky: t!("finding.host.docker_socket_world_writable.why").into_owned(),
                    how_to_fix: t!("finding.host.docker_socket_world_writable.fix").into_owned(),
                },
                BTreeMap::from([
                    (String::from("path"), socket_path.display().to_string()),
                    (String::from("mode"), format_permissions(mode)),
                ]),
            ));
        } else if mode & 0o004 != 0 {
            findings.push(host_finding(
                "host.docker_socket_world_readable",
                Severity::High,
                &socket_path,
                HostFindingText {
                    title: t!("finding.host.docker_socket_world_readable.title").into_owned(),
                    description: t!(
                        "finding.host.docker_socket_world_readable.description",
                        path = socket_path.display().to_string(),
                        mode = format_permissions(mode)
                    )
                    .into_owned(),
                    why_risky: t!("finding.host.docker_socket_world_readable.why").into_owned(),
                    how_to_fix: t!("finding.host.docker_socket_world_readable.fix").into_owned(),
                },
                BTreeMap::from([
                    (String::from("path"), socket_path.display().to_string()),
                    (String::from("mode"), format_permissions(mode)),
                ]),
            ));
        }
    }

    if let Some(daemon_path) = resolve_existing_path(&context.root, DOCKER_DAEMON_CONFIG_PATH)
        && let Ok(text) = fs::read_to_string(&daemon_path)
        && let Ok(json) = serde_json::from_str::<JsonValue>(&text)
    {
        if daemon_hosts_include_public_tcp(&json) {
            findings.push(host_finding(
                "host.docker_daemon_tcp_public",
                Severity::High,
                &daemon_path,
                HostFindingText {
                    title: t!("finding.host.docker_daemon_tcp_public.title").into_owned(),
                    description: t!(
                        "finding.host.docker_daemon_tcp_public.description",
                        path = daemon_path.display().to_string()
                    )
                    .into_owned(),
                    why_risky: t!("finding.host.docker_daemon_tcp_public.why").into_owned(),
                    how_to_fix: t!("finding.host.docker_daemon_tcp_public.fix").into_owned(),
                },
                BTreeMap::from([(String::from("path"), daemon_path.display().to_string())]),
            ));

            if !daemon_tlsverify_enabled(&json) {
                findings.push(host_finding(
                    "host.docker_daemon_tcp_no_tlsverify",
                    Severity::Critical,
                    &daemon_path,
                    HostFindingText {
                        title: t!("finding.host.docker_daemon_tcp_no_tlsverify.title").into_owned(),
                        description: t!(
                            "finding.host.docker_daemon_tcp_no_tlsverify.description",
                            path = daemon_path.display().to_string()
                        )
                        .into_owned(),
                        why_risky: t!("finding.host.docker_daemon_tcp_no_tlsverify.why")
                            .into_owned(),
                        how_to_fix: t!("finding.host.docker_daemon_tcp_no_tlsverify.fix")
                            .into_owned(),
                    },
                    BTreeMap::from([
                        (String::from("path"), daemon_path.display().to_string()),
                        (
                            String::from("tlsverify"),
                            docker_daemon_setting_state(&json, "tlsverify"),
                        ),
                    ]),
                ));
            }
        }

        if docker_daemon_iptables_disabled(&json) {
            findings.push(host_finding(
                "host.docker_daemon_iptables_disabled",
                Severity::High,
                &daemon_path,
                HostFindingText {
                    title: t!("finding.host.docker_daemon_iptables_disabled.title").into_owned(),
                    description: t!(
                        "finding.host.docker_daemon_iptables_disabled.description",
                        path = daemon_path.display().to_string()
                    )
                    .into_owned(),
                    why_risky: t!("finding.host.docker_daemon_iptables_disabled.why").into_owned(),
                    how_to_fix: t!("finding.host.docker_daemon_iptables_disabled.fix").into_owned(),
                },
                BTreeMap::from([
                    (String::from("path"), daemon_path.display().to_string()),
                    (String::from("iptables"), String::from("false")),
                ]),
            ));
        }
    }

    if is_live_root(&context.root)
        && let Some(false) = docker_is_rootless()
    {
        findings.push(host_finding(
            "host.docker_not_rootless",
            Severity::Low,
            &context.root.join(DOCKER_SOCKET_PATH),
            HostFindingText {
                title: t!("finding.host.docker_not_rootless.title").into_owned(),
                description: t!("finding.host.docker_not_rootless.description").into_owned(),
                why_risky: t!("finding.host.docker_not_rootless.why").into_owned(),
                how_to_fix: t!("finding.host.docker_not_rootless.fix").into_owned(),
            },
            BTreeMap::new(),
        ));
    }

    findings
}

fn docker_is_rootless() -> Option<bool> {
    let output = try_command(&["docker", "info"])?;
    Some(output.to_ascii_lowercase().contains("rootless"))
fn scan_docker_daemon_hardening(context: &HostContext) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Some(daemon_path) = resolve_existing_path(&context.root, DOCKER_DAEMON_CONFIG_PATH)
        && let Ok(text) = fs::read_to_string(&daemon_path)
        && let Ok(json) = serde_json::from_str::<JsonValue>(&text)
    {

    if !docker_daemon_userns_remapped(&json) {
        findings.push(host_finding(
            "host.docker_userns_remap_missing",
            Severity::Medium,
            &daemon_path,
            HostFindingText {
                title: t!("finding.host.docker_userns_remap_missing.title").into_owned(),
                description: t!(
                    "finding.host.docker_userns_remap_missing.description",
                    path = daemon_path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.docker_userns_remap_missing.why").into_owned(),
                how_to_fix: t!("finding.host.docker_userns_remap_missing.fix").into_owned(),
            },
            BTreeMap::from([(String::from("path"), daemon_path.display().to_string())]),
        ));
    }

    if !docker_daemon_live_restore_enabled(&json) {
        findings.push(host_finding(
            "host.docker_live_restore_disabled",
            Severity::Medium,
            &daemon_path,
            HostFindingText {
                title: t!("finding.host.docker_live_restore_disabled.title").into_owned(),
                description: t!(
                    "finding.host.docker_live_restore_disabled.description",
                    path = daemon_path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.docker_live_restore_disabled.why").into_owned(),
                how_to_fix: t!("finding.host.docker_live_restore_disabled.fix").into_owned(),
            },
            BTreeMap::from([(String::from("path"), daemon_path.display().to_string())]),
        ));
    }

    if !docker_daemon_log_driver_configured(&json) {
        findings.push(host_finding(
            "host.docker_log_driver_missing",
            Severity::Low,
            &daemon_path,
            HostFindingText {
                title: t!("finding.host.docker_log_driver_missing.title").into_owned(),
                description: t!(
                    "finding.host.docker_log_driver_missing.description",
                    path = daemon_path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.docker_log_driver_missing.why").into_owned(),
                how_to_fix: t!("finding.host.docker_log_driver_missing.fix").into_owned(),
            },
            BTreeMap::from([(String::from("path"), daemon_path.display().to_string())]),
        ));
    }

    if !docker_daemon_default_ulimits_configured(&json) {
        findings.push(host_finding(
            "host.docker_default_ulimits_missing",
            Severity::Low,
            &daemon_path,
            HostFindingText {
                title: t!("finding.host.docker_default_ulimits_missing.title").into_owned(),
                description: t!(
                    "finding.host.docker_default_ulimits_missing.description",
                    path = daemon_path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.docker_default_ulimits_missing.why").into_owned(),
                how_to_fix: t!("finding.host.docker_default_ulimits_missing.fix").into_owned(),
            },
            BTreeMap::from([(String::from("path"), daemon_path.display().to_string())]),
        ));
    }
    }

    findings
}

fn scan_firewall_hardening(context: &HostContext) -> Vec<Finding> {
    let mut findings = Vec::new();

    if detect_ufw_installed(&context.root) {
        findings.extend(scan_ufw_hardening(context));
        return findings;
    }

    if detect_firewalld_installed(&context.root) {
        findings.extend(scan_firewalld_hardening(context));
        return findings;
    }

    if detect_nftables_installed(&context.root) {
        findings.extend(scan_nftables_hardening(context));
        return findings;
    }

    findings.push(host_finding(
        "host.no_firewall_detected",
        Severity::Medium,
        &context.root,
        HostFindingText {
            title: t!("finding.host.no_firewall_detected.title").into_owned(),
            description: t!("finding.host.no_firewall_detected.description").into_owned(),
            why_risky: t!("finding.host.no_firewall_detected.why").into_owned(),
            how_to_fix: t!("finding.host.no_firewall_detected.fix").into_owned(),
        },
        BTreeMap::new(),
    ));

    findings
}

fn scan_ufw_hardening(context: &HostContext) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Some(config_path) = resolve_existing_path(&context.root, UFW_CONFIG_PATH)
        && let Ok(config_text) = fs::read_to_string(&config_path)
        && let Some(enabled) = parse_ufw_enabled(&config_text)
        && !enabled
    {
        findings.push(host_finding(
            "host.ufw_installed_but_disabled",
            Severity::Medium,
            &config_path,
            HostFindingText {
                title: t!("finding.host.ufw_disabled.title").into_owned(),
                description: t!(
                    "finding.host.ufw_disabled.description",
                    path = config_path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.ufw_disabled.why").into_owned(),
                how_to_fix: t!("finding.host.ufw_disabled.fix").into_owned(),
            },
            BTreeMap::from([
                (String::from("path"), config_path.display().to_string()),
                (String::from("enabled"), String::from("no")),
            ]),
        ));
    }

    if let Some(defaults_path) = resolve_existing_path(&context.root, UFW_DEFAULT_POLICY_PATH)
        && let Ok(defaults_text) = fs::read_to_string(&defaults_path)
        && let Some(policy) = parse_ufw_default_input_policy(&defaults_text)
        && policy.eq_ignore_ascii_case("accept")
    {
        findings.push(host_finding(
            "host.ufw_default_input_policy_accept",
            Severity::Medium,
            &defaults_path,
            HostFindingText {
                title: t!("finding.host.ufw_default_input_policy_accept.title").into_owned(),
                description: t!(
                    "finding.host.ufw_default_input_policy_accept.description",
                    path = defaults_path.display().to_string(),
                    policy = policy.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.host.ufw_default_input_policy_accept.why").into_owned(),
                how_to_fix: t!("finding.host.ufw_default_input_policy_accept.fix").into_owned(),
            },
            BTreeMap::from([
                (String::from("path"), defaults_path.display().to_string()),
                (String::from("policy"), policy),
            ]),
        ));
    }

    findings
}

fn detect_firewalld_installed(root: &Path) -> bool {
    resolve_existing_path(root, FIREWALLD_CONFIG_PATH).is_some()
        || FIREWALLD_CMD_PATHS
            .iter()
            .any(|path| resolve_existing_path(root, path).is_some())
        || FIREWALLD_SERVICE_PATHS
            .iter()
            .any(|path| resolve_existing_path(root, path).is_some())
}

fn detect_firewalld_enabled(root: &Path) -> bool {
    FIREWALLD_ENABLED_MARKERS
        .iter()
        .any(|marker| resolve_existing_path(root, marker).is_some())
}

fn scan_firewalld_hardening(context: &HostContext) -> Vec<Finding> {
    let mut findings = Vec::new();

    if !detect_firewalld_enabled(&context.root) {
        let config_path = resolve_existing_path(&context.root, FIREWALLD_CONFIG_PATH)
            .or_else(|| resolve_existing_path(&context.root, FIREWALLD_SERVICE_PATHS[0]))
            .unwrap_or_else(|| context.root.join(FIREWALLD_CONFIG_PATH));

        findings.push(host_finding(
            "host.firewalld_installed_but_disabled",
            Severity::Medium,
            &config_path,
            HostFindingText {
                title: t!("finding.host.firewalld_installed_but_disabled.title").into_owned(),
                description: t!(
                    "finding.host.firewalld_installed_but_disabled.description",
                    path = config_path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.firewalld_installed_but_disabled.why").into_owned(),
                how_to_fix: t!("finding.host.firewalld_installed_but_disabled.fix").into_owned(),
            },
            BTreeMap::from([
                (String::from("path"), config_path.display().to_string()),
                (String::from("enabled"), String::from("no")),
            ]),
        ));
        return findings;
    }

    if let Some(config_path) = resolve_existing_path(&context.root, FIREWALLD_CONFIG_PATH)
        && let Ok(text) = fs::read_to_string(&config_path)
        && let Some(zone) = parse_firewalld_default_zone(&text)
        && zone.eq_ignore_ascii_case("trusted")
    {
        findings.push(host_finding(
            "host.firewalld_default_zone_trusted",
            Severity::High,
            &config_path,
            HostFindingText {
                title: t!("finding.host.firewalld_default_zone_trusted.title").into_owned(),
                description: t!(
                    "finding.host.firewalld_default_zone_trusted.description",
                    path = config_path.display().to_string(),
                    zone = zone.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.host.firewalld_default_zone_trusted.why").into_owned(),
                how_to_fix: t!("finding.host.firewalld_default_zone_trusted.fix").into_owned(),
            },
            BTreeMap::from([
                (String::from("path"), config_path.display().to_string()),
                (String::from("zone"), zone),
            ]),
        ));
    }

    findings
}

fn parse_firewalld_default_zone(text: &str) -> Option<String> {
    for raw_line in text.lines() {
        let line = strip_ini_comments(raw_line);
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = parse_ini_key_value(line) else {
            continue;
        };
        if !key.eq_ignore_ascii_case("DefaultZone") {
            continue;
        }
        let zone = value.trim_matches('"').trim_matches('\'').trim();
        if zone.is_empty() {
            continue;
        }
        return Some(zone.to_owned());
    }
    None
}

fn detect_nftables_installed(root: &Path) -> bool {
    resolve_existing_path(root, NFTABLES_CONF_PATH).is_some()
        || NFT_PATHS
            .iter()
            .any(|path| resolve_existing_path(root, path).is_some())
}

fn scan_nftables_hardening(context: &HostContext) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Some(conf_path) = resolve_existing_path(&context.root, NFTABLES_CONF_PATH)
        && let Ok(text) = fs::read_to_string(&conf_path)
        && text.trim().is_empty()
    {
        findings.push(host_finding(
            "host.nftables_installed_no_rules",
            Severity::Medium,
            &conf_path,
            HostFindingText {
                title: t!("finding.host.nftables_installed_no_rules.title").into_owned(),
                description: t!(
                    "finding.host.nftables_installed_no_rules.description",
                    path = conf_path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.nftables_installed_no_rules.why").into_owned(),
                how_to_fix: t!("finding.host.nftables_installed_no_rules.fix").into_owned(),
            },
            BTreeMap::from([(String::from("path"), conf_path.display().to_string())]),
        ));
    }

    findings
}

fn scan_mac_frameworks(context: &HostContext) -> Vec<Finding> {
    let mut findings = Vec::new();

    let selinux_installed = resolve_existing_path(&context.root, "etc/selinux/config").is_some()
        || resolve_existing_path(&context.root, "sys/fs/selinux").is_some();

    if selinux_installed {
        let mode = read_selinux_mode(&context.root);
        match mode.as_deref() {
            Some("enforcing") => {}
            Some("permissive") => {
                findings.push(host_finding(
                    "host.selinux_permissive",
                    Severity::Medium,
                    &context.root.join("etc/selinux/config"),
                    HostFindingText {
                        title: t!("finding.host.selinux_permissive.title").into_owned(),
                        description: t!(
                            "finding.host.selinux_permissive.description",
                            path = context
                                .root
                                .join("etc/selinux/config")
                                .display()
                                .to_string()
                        )
                        .into_owned(),
                        why_risky: t!("finding.host.selinux_permissive.why").into_owned(),
                        how_to_fix: t!("finding.host.selinux_permissive.fix").into_owned(),
                    },
                    BTreeMap::from([(String::from("mode"), String::from("permissive"))]),
                ));
            }
            Some("disabled") | None => {
                findings.push(host_finding(
                    "host.selinux_disabled",
                    Severity::Medium,
                    &context.root.join("etc/selinux/config"),
                    HostFindingText {
                        title: t!("finding.host.selinux_disabled.title").into_owned(),
                        description: t!(
                            "finding.host.selinux_disabled.description",
                            path = context
                                .root
                                .join("etc/selinux/config")
                                .display()
                                .to_string()
                        )
                        .into_owned(),
                        why_risky: t!("finding.host.selinux_disabled.why").into_owned(),
                        how_to_fix: t!("finding.host.selinux_disabled.fix").into_owned(),
                    },
                    BTreeMap::from([(String::from("mode"), String::from("disabled"))]),
                ));
            }
            _ => {}
        }
    }

    let apparmor_present =
        resolve_existing_path(&context.root, "sys/kernel/security/apparmor").is_some();
    let apparmor_profiles = apparmor_present
        .then(|| read_sysctl(context, "sys/kernel/security/apparmor/profiles"))
        .flatten();

    if let Some(ref profiles) = apparmor_profiles
        && profiles.contains(" (complain)")
    {
        findings.push(host_finding(
            "host.apparmor_complain_mode",
            Severity::Medium,
            &context.root.join("sys/kernel/security/apparmor/profiles"),
            HostFindingText {
                title: t!("finding.host.apparmor_complain_mode.title").into_owned(),
                description: t!(
                    "finding.host.apparmor_complain_mode.description",
                    path = context
                        .root
                        .join("sys/kernel/security/apparmor/profiles")
                        .display()
                        .to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.apparmor_complain_mode.why").into_owned(),
                how_to_fix: t!("finding.host.apparmor_complain_mode.fix").into_owned(),
            },
            BTreeMap::new(),
        ));
    }

    if let Some(ref profiles) = apparmor_profiles {
        let expected_services = [("docker", "docker"), ("nginx", "nginx"), ("sshd", "sshd")];
        for (service, pattern) in expected_services {
            let has_profile = profiles
                .lines()
                .any(|line| line.to_lowercase().contains(pattern));
            if !has_profile {
                findings.push(host_finding(
                    &format!("host.apparmor_{service}_profile_missing"),
                    Severity::Low,
                    &context.root.join("sys/kernel/security/apparmor/profiles"),
                    HostFindingText {
                        title: t!(
                            "finding.host.apparmor_profile_missing.title",
                            service = service
                        )
                        .into_owned(),
                        description: t!(
                            "finding.host.apparmor_profile_missing.description",
                            service = service,
                            path = context
                                .root
                                .join("sys/kernel/security/apparmor/profiles")
                                .display()
                                .to_string()
                        )
                        .into_owned(),
                        why_risky: t!("finding.host.apparmor_profile_missing.why")
                            .into_owned(),
                        how_to_fix: t!("finding.host.apparmor_profile_missing.fix")
                            .into_owned(),
                    },
                    BTreeMap::from([(String::from("service"), String::from(service))]),
                ));
            }
        }
    }

    if !selinux_installed && !apparmor_present {
        findings.push(host_finding(
            "host.mac_framework_missing",
            Severity::Low,
            &context.root,
            HostFindingText {
                title: t!("finding.host.mac_framework_missing.title").into_owned(),
                description: t!(
                    "finding.host.mac_framework_missing.description",
                    path = context.root.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.mac_framework_missing.why").into_owned(),
                how_to_fix: t!("finding.host.mac_framework_missing.fix").into_owned(),
            },
            BTreeMap::new(),
        ));
    }

    findings
}

fn read_selinux_mode(root: &Path) -> Option<String> {
    let path = root.join("etc/selinux/config");
    let text = fs::read_to_string(&path).ok()?;
    for line in text.lines() {
        let stripped = line.split('#').next().unwrap_or("").trim();
        if stripped.is_empty() {
            continue;
        }
        let Some((key, value)) = stripped.split_once('=') else {
            continue;
        };
        if key.trim().eq_ignore_ascii_case("SELINUX") {
            return Some(value.trim().to_ascii_lowercase());
        }
    }
    None
}

fn scan_kernel_hardening(context: &HostContext) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Some(value) = read_sysctl(context, "proc/sys/kernel/randomize_va_space")
        && value.trim() == "0"
    {
        findings.push(host_finding(
            "host.kernel.aslr_disabled",
            Severity::High,
            &context.root.join("proc/sys/kernel/randomize_va_space"),
            HostFindingText {
                title: t!("finding.host.kernel_aslr_disabled.title").into_owned(),
                description: t!(
                    "finding.host.kernel_aslr_disabled.description",
                    path = context
                        .root
                        .join("proc/sys/kernel/randomize_va_space")
                        .display()
                        .to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.kernel_aslr_disabled.why").into_owned(),
                how_to_fix: t!("finding.host.kernel_aslr_disabled.fix").into_owned(),
            },
            BTreeMap::from([(String::from("value"), String::from("0"))]),
        ));
    }

    if let Some(value) = read_sysctl(context, "proc/sys/net/ipv4/tcp_syncookies")
        && value.trim() == "0"
    {
        findings.push(host_finding(
            "host.kernel.syn_cookies_disabled",
            Severity::Medium,
            &context.root.join("proc/sys/net/ipv4/tcp_syncookies"),
            HostFindingText {
                title: t!("finding.host.kernel_syn_cookies_disabled.title").into_owned(),
                description: t!(
                    "finding.host.kernel_syn_cookies_disabled.description",
                    path = context
                        .root
                        .join("proc/sys/net/ipv4/tcp_syncookies")
                        .display()
                        .to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.kernel_syn_cookies_disabled.why").into_owned(),
                how_to_fix: t!("finding.host.kernel_syn_cookies_disabled.fix").into_owned(),
            },
            BTreeMap::from([(String::from("value"), String::from("0"))]),
        ));
    }

    if let Some(value) = read_sysctl(context, "proc/sys/net/ipv4/icmp_echo_ignore_broadcasts")
        && value.trim() == "0"
    {
        findings.push(host_finding(
            "host.kernel.broadcast_ping_allowed",
            Severity::Low,
            &context
                .root
                .join("proc/sys/net/ipv4/icmp_echo_ignore_broadcasts"),
            HostFindingText {
                title: t!("finding.host.kernel_broadcast_ping_allowed.title").into_owned(),
                description: t!(
                    "finding.host.kernel_broadcast_ping_allowed.description",
                    path = context
                        .root
                        .join("proc/sys/net/ipv4/icmp_echo_ignore_broadcasts")
                        .display()
                        .to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.kernel_broadcast_ping_allowed.why").into_owned(),
                how_to_fix: t!("finding.host.kernel_broadcast_ping_allowed.fix").into_owned(),
            },
            BTreeMap::from([(String::from("value"), String::from("0"))]),
        ));
    }

    let docker_present = resolve_existing_path(&context.root, DOCKER_SOCKET_PATH).is_some();
    if !docker_present
        && let Some(value) = read_sysctl(context, "proc/sys/net/ipv4/ip_forward")
        && value.trim() == "1"
    {
        findings.push(host_finding(
            "host.kernel.ip_forward_enabled",
            Severity::Medium,
            &context.root.join("proc/sys/net/ipv4/ip_forward"),
            HostFindingText {
                title: t!("finding.host.kernel_ip_forward_enabled.title").into_owned(),
                description: t!(
                    "finding.host.kernel_ip_forward_enabled.description",
                    path = context
                        .root
                        .join("proc/sys/net/ipv4/ip_forward")
                        .display()
                        .to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.kernel_ip_forward_enabled.why").into_owned(),
                how_to_fix: t!("finding.host.kernel_ip_forward_enabled.fix").into_owned(),
            },
            BTreeMap::from([(String::from("value"), String::from("1"))]),
        ));
    }

    if let Some(value) = read_sysctl(context, "proc/sys/kernel/modules_disabled")
        && value.trim() == "0"
    {
        findings.push(host_finding(
            "host.kernel.modules_disabled_not_set",
            Severity::Medium,
            &context.root.join("proc/sys/kernel/modules_disabled"),
            HostFindingText {
                title: t!("finding.host.kernel_modules_disabled_not_set.title").into_owned(),
                description: t!(
                    "finding.host.kernel_modules_disabled_not_set.description",
                    path = context
                        .root
                        .join("proc/sys/kernel/modules_disabled")
                        .display()
                        .to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.kernel_modules_disabled_not_set.why").into_owned(),
                how_to_fix: t!("finding.host.kernel_modules_disabled_not_set.fix").into_owned(),
            },
            BTreeMap::from([(String::from("value"), String::from("0"))]),
        ));
    }

    let sig_enforce_path = "sys/module/module/parameters/sig_enforce";
    let sig_enforce_value = read_sysctl(context, sig_enforce_path);
    let sig_enforce_missing = sig_enforce_value.is_none();
    let sig_enforce_disabled = sig_enforce_value.as_deref().is_some_and(|v| v.trim() == "N");

    if sig_enforce_missing || sig_enforce_disabled {
        findings.push(host_finding(
            "host.kernel.module_signing_not_enforced",
            Severity::Low,
            &context.root.join(sig_enforce_path),
            HostFindingText {
                title: t!("finding.host.kernel_module_signing_not_enforced.title").into_owned(),
                description: t!(
                    "finding.host.kernel_module_signing_not_enforced.description",
                    path = context.root.join(sig_enforce_path).display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.kernel_module_signing_not_enforced.why")
                    .into_owned(),
                how_to_fix: t!("finding.host.kernel_module_signing_not_enforced.fix")
                    .into_owned(),
            },
            BTreeMap::from([(
                String::from("state"),
                if sig_enforce_missing {
                    String::from("missing")
                } else {
                    String::from("disabled")
                },
            )]),
        ));
    }

    findings
}

fn scan_user_namespace_settings(context: &HostContext) -> Vec<Finding> {
    let mut findings = Vec::new();
    let docker_present = resolve_existing_path(&context.root, DOCKER_SOCKET_PATH).is_some();

    if docker_present {
        return findings;
    }

    if let Some(value) = read_sysctl(context, "proc/sys/kernel/unprivileged_userns_clone")
        && value.trim() == "1"
    {
        findings.push(host_finding(
            "host.kernel.unprivileged_userns_clone_enabled",
            Severity::Medium,
            &context
                .root
                .join("proc/sys/kernel/unprivileged_userns_clone"),
            HostFindingText {
                title: t!("finding.host.kernel_unprivileged_userns_clone_enabled.title")
                    .into_owned(),
                description: t!(
                    "finding.host.kernel_unprivileged_userns_clone_enabled.description",
                    path = context
                        .root
                        .join("proc/sys/kernel/unprivileged_userns_clone")
                        .display()
                        .to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.kernel_unprivileged_userns_clone_enabled.why")
                    .into_owned(),
                how_to_fix: t!("finding.host.kernel_unprivileged_userns_clone_enabled.fix")
                    .into_owned(),
            },
            BTreeMap::from([(String::from("value"), String::from("1"))]),
        ));
    }

    if let Some(value) = read_sysctl(context, "proc/sys/user/max_user_namespaces")
        && value.trim().parse::<u64>().unwrap_or(1) > 0
    {
        findings.push(host_finding(
            "host.kernel.max_user_namespaces_enabled",
            Severity::Low,
            &context.root.join("proc/sys/user/max_user_namespaces"),
            HostFindingText {
                title: t!("finding.host.kernel_max_user_namespaces_enabled.title").into_owned(),
                description: t!(
                    "finding.host.kernel_max_user_namespaces_enabled.description",
                    path = context
                        .root
                        .join("proc/sys/user/max_user_namespaces")
                        .display()
                        .to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.kernel_max_user_namespaces_enabled.why").into_owned(),
                how_to_fix: t!("finding.host.kernel_max_user_namespaces_enabled.fix").into_owned(),
            },
            BTreeMap::from([(String::from("value"), value.trim().to_owned())]),
        ));
    }

    findings
}

fn read_sysctl(context: &HostContext, relative: &str) -> Option<String> {
    let path = context.root.join(relative);
    let text = fs::read_to_string(&path).ok()?;
    let trimmed = text.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

fn scan_package_update_hardening(context: &HostContext) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(scan_apt_auto_upgrades(context));
    findings.extend(scan_dnf_auto_updates(context));
    findings.extend(scan_yum_cron(context));
    findings
}

fn scan_apt_auto_upgrades(context: &HostContext) -> Vec<Finding> {
    let Some(config_path) = resolve_existing_path(&context.root, APT_AUTO_UPGRADES_CONFIG_PATH)
    else {
        return Vec::new();
    };

    let Ok(config_text) = fs::read_to_string(&config_path) else {
        return Vec::new();
    };

    let mut findings = Vec::new();

    if let Some(enabled) = parse_unattended_upgrades_enabled(&config_text)
        && !enabled
    {
        findings.push(host_finding(
            "host.apt_unattended_upgrades_disabled",
            Severity::Medium,
            &config_path,
            HostFindingText {
                title: t!("finding.host.unattended_upgrades_disabled.title").into_owned(),
                description: t!(
                    "finding.host.unattended_upgrades_disabled.description",
                    path = config_path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.unattended_upgrades_disabled.why").into_owned(),
                how_to_fix: t!("finding.host.unattended_upgrades_disabled.fix").into_owned(),
            },
            BTreeMap::from([
                (String::from("path"), config_path.display().to_string()),
                (String::from("unattended_upgrade"), String::from("disabled")),
            ]),
        ));
    }

    if let Some(enabled) = parse_package_lists_auto_update_enabled(&config_text)
        && !enabled
    {
        findings.push(host_finding(
            "host.apt_package_lists_auto_update_disabled",
            Severity::Low,
            &config_path,
            HostFindingText {
                title: t!("finding.host.package_lists_auto_update_disabled.title").into_owned(),
                description: t!(
                    "finding.host.package_lists_auto_update_disabled.description",
                    path = config_path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.package_lists_auto_update_disabled.why").into_owned(),
                how_to_fix: t!("finding.host.package_lists_auto_update_disabled.fix").into_owned(),
            },
            BTreeMap::from([
                (String::from("path"), config_path.display().to_string()),
                (
                    String::from("update_package_lists"),
                    String::from("disabled"),
                ),
            ]),
        ));
    }

    findings
}

fn scan_dnf_auto_updates(context: &HostContext) -> Vec<Finding> {
    let Some(config_path) = resolve_existing_path(&context.root, DNF_AUTOMATIC_CONF_PATH) else {
        return Vec::new();
    };

    let Ok(config_text) = fs::read_to_string(&config_path) else {
        return Vec::new();
    };

    let mut findings = Vec::new();

    if let Some(enabled) = parse_ini_bool_in_section(&config_text, "commands", "apply_updates")
        && !enabled
    {
        findings.push(host_finding(
            "host.dnf_automatic_disabled",
            Severity::Medium,
            &config_path,
            HostFindingText {
                title: t!("finding.host.dnf_automatic_disabled.title").into_owned(),
                description: t!(
                    "finding.host.dnf_automatic_disabled.description",
                    path = config_path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.dnf_automatic_disabled.why").into_owned(),
                how_to_fix: t!("finding.host.dnf_automatic_disabled.fix").into_owned(),
            },
            BTreeMap::from([
                (String::from("path"), config_path.display().to_string()),
                (String::from("apply_updates"), String::from("disabled")),
            ]),
        ));
    }

    if !DNF_AUTOMATIC_TIMER_ENABLED
        .iter()
        .any(|marker| resolve_existing_path(&context.root, marker).is_some())
    {
        findings.push(host_finding(
            "host.dnf_automatic_timer_disabled",
            Severity::Medium,
            &config_path,
            HostFindingText {
                title: t!("finding.host.dnf_automatic_timer_disabled.title").into_owned(),
                description: t!(
                    "finding.host.dnf_automatic_timer_disabled.description",
                    path = config_path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.dnf_automatic_timer_disabled.why").into_owned(),
                how_to_fix: t!("finding.host.dnf_automatic_timer_disabled.fix").into_owned(),
            },
            BTreeMap::from([
                (String::from("path"), config_path.display().to_string()),
                (String::from("timer"), String::from("disabled")),
            ]),
        ));
    }

    findings
}

fn scan_yum_cron(context: &HostContext) -> Vec<Finding> {
    let Some(config_path) = resolve_existing_path(&context.root, YUM_CRON_CONF_PATH) else {
        return Vec::new();
    };

    let Ok(config_text) = fs::read_to_string(&config_path) else {
        return Vec::new();
    };

    let mut findings = Vec::new();

    if let Some(enabled) = parse_ini_bool_in_section(&config_text, "commands", "apply_updates")
        && !enabled
    {
        findings.push(host_finding(
            "host.yum_cron_disabled",
            Severity::Medium,
            &config_path,
            HostFindingText {
                title: t!("finding.host.yum_cron_disabled.title").into_owned(),
                description: t!(
                    "finding.host.yum_cron_disabled.description",
                    path = config_path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.yum_cron_disabled.why").into_owned(),
                how_to_fix: t!("finding.host.yum_cron_disabled.fix").into_owned(),
            },
            BTreeMap::from([
                (String::from("path"), config_path.display().to_string()),
                (String::from("apply_updates"), String::from("disabled")),
            ]),
        ));
    }

    if !YUM_CRON_SERVICE_ENABLED
        .iter()
        .any(|marker| resolve_existing_path(&context.root, marker).is_some())
    {
        findings.push(host_finding(
            "host.yum_cron_service_disabled",
            Severity::Medium,
            &config_path,
            HostFindingText {
                title: t!("finding.host.yum_cron_service_disabled.title").into_owned(),
                description: t!(
                    "finding.host.yum_cron_service_disabled.description",
                    path = config_path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.yum_cron_service_disabled.why").into_owned(),
                how_to_fix: t!("finding.host.yum_cron_service_disabled.fix").into_owned(),
            },
            BTreeMap::from([
                (String::from("path"), config_path.display().to_string()),
                (String::from("service"), String::from("disabled")),
            ]),
        ));
    }

    findings
}

fn parse_ini_bool_in_section(text: &str, target_section: &str, target_key: &str) -> Option<bool> {
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

fn scan_mount_flags(context: &HostContext) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mounts_path = context.root.join("proc/mounts");

    let text = match fs::read_to_string(&mounts_path) {
        Ok(text) => text,
        Err(_) => return findings,
    };

    let mounts = parse_proc_mounts(&text);

    let sensitive_mounts: [(&str, &[&str]); 4] = [
        ("/tmp", &["noexec", "nosuid", "nodev"]),
        ("/home", &["noexec", "nosuid", "nodev"]),
        ("/var", &["noexec", "nosuid", "nodev"]),
        ("/boot", &["noexec", "nosuid", "nodev"]),
    ];

    for (mount_point, expected_flags) in &sensitive_mounts {
        let Some(options) = mounts.get(*mount_point) else {
            continue;
        };

        let missing: Vec<&str> = expected_flags
            .iter()
            .filter(|flag| !options.iter().any(|opt| opt == **flag))
            .copied()
            .collect();

        if missing.is_empty() {
            continue;
        }

        findings.push(host_finding(
            "host.mount_flags_missing",
            Severity::Medium,
            &mounts_path,
            HostFindingText {
                title: t!("finding.host.mount_flags_missing.title").into_owned(),
                description: t!(
                    "finding.host.mount_flags_missing.description",
                    mount_point = mount_point,
                    flags = missing.join(", ")
                )
                .into_owned(),
                why_risky: t!("finding.host.mount_flags_missing.why").into_owned(),
                how_to_fix: t!("finding.host.mount_flags_missing.fix").into_owned(),
            },
            BTreeMap::from([
                (String::from("mount_point"), mount_point.to_string()),
                (String::from("missing_flags"), missing.join(", ")),
            ]),
        ));
    }

    findings
}

fn parse_proc_mounts(text: &str) -> BTreeMap<String, Vec<String>> {
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

fn scan_proc_hidepid(context: &HostContext) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mounts_path = context.root.join("proc/mounts");

    let text = match fs::read_to_string(&mounts_path) {
        Ok(text) => text,
        Err(_) => return findings,
    };

    let mounts = parse_proc_mounts(&text);
    let options = match mounts.get("/proc") {
        Some(options) => options,
        None => {
            findings.push(host_finding(
                "host.proc_hidepid_missing",
                Severity::Medium,
                &mounts_path,
                HostFindingText {
                    title: t!("finding.host.proc_hidepid_missing.title").into_owned(),
                    description: t!("finding.host.proc_hidepid_missing.description").into_owned(),
                    why_risky: t!("finding.host.proc_hidepid_missing.why").into_owned(),
                    how_to_fix: t!("finding.host.proc_hidepid_missing.fix").into_owned(),
                },
                BTreeMap::new(),
            ));
            return findings;
        }
    };

    let has_hidepid = options.iter().any(|opt| opt.starts_with("hidepid="));
    let hidepid_hardened = options
        .iter()
        .any(|opt| opt == "hidepid=2" || opt == "hidepid=1");

    if !has_hidepid {
        findings.push(host_finding(
            "host.proc_hidepid_missing",
            Severity::Medium,
            &mounts_path,
            HostFindingText {
                title: t!("finding.host.proc_hidepid_missing.title").into_owned(),
                description: t!("finding.host.proc_hidepid_missing.description").into_owned(),
                why_risky: t!("finding.host.proc_hidepid_missing.why").into_owned(),
                how_to_fix: t!("finding.host.proc_hidepid_missing.fix").into_owned(),
            },
            BTreeMap::new(),
        ));
    } else if !hidepid_hardened {
        findings.push(host_finding(
            "host.proc_hidepid_weak",
            Severity::Low,
            &mounts_path,
            HostFindingText {
                title: t!("finding.host.proc_hidepid_weak.title").into_owned(),
                description: t!("finding.host.proc_hidepid_weak.description").into_owned(),
                why_risky: t!("finding.host.proc_hidepid_weak.why").into_owned(),
                how_to_fix: t!("finding.host.proc_hidepid_weak.fix").into_owned(),
            },
            BTreeMap::new(),
        ));
    }

    findings
}

const SYSTEMD_SERVICE_DIRS: [&str; 2] = ["etc/systemd/system", "lib/systemd/system"];
const SYSTEMD_HARDENING_MARKERS: [&str; 4] = [
    "NoNewPrivileges",
    "ProtectSystem",
    "ProtectHome",
    "PrivateTmp",
];
const SYSTEMD_HARDENING_SAMPLE_SERVICES: [&str; 4] = [
    "sshd.service",
    "docker.service",
    "nginx.service",
    "fail2ban.service",
];

fn scan_systemd_hardening(context: &HostContext) -> Vec<Finding> {
    let mut findings = Vec::new();

    for service_name in SYSTEMD_HARDENING_SAMPLE_SERVICES {
        let Some(path) = find_systemd_service_path(context, service_name) else {
            continue;
        };

        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(_) => continue,
        };

        let missing: Vec<&str> = SYSTEMD_HARDENING_MARKERS
            .iter()
            .filter(|marker| !text.contains(**marker))
            .copied()
            .collect();

        if missing.is_empty() {
            continue;
        }

        findings.push(host_finding(
            "host.systemd_hardening_missing",
            Severity::Low,
            &path,
            HostFindingText {
                title: t!("finding.host.systemd_hardening_missing.title").into_owned(),
                description: t!(
                    "finding.host.systemd_hardening_missing.description",
                    service = service_name,
                    flags = missing.join(", ")
                )
                .into_owned(),
                why_risky: t!("finding.host.systemd_hardening_missing.why").into_owned(),
                how_to_fix: t!("finding.host.systemd_hardening_missing.fix").into_owned(),
            },
            BTreeMap::from([
                (String::from("service"), service_name.to_owned()),
                (String::from("missing_flags"), missing.join(", ")),
            ]),
        ));
    }

    findings
}

fn find_systemd_service_path(context: &HostContext, name: &str) -> Option<PathBuf> {
    for dir in SYSTEMD_SERVICE_DIRS {
        let candidate = context.root.join(dir).join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn detect_ufw_installed(root: &Path) -> bool {
    UFW_INSTALL_MARKERS
        .iter()
        .any(|marker| resolve_existing_path(root, marker).is_some())
}

fn parse_ufw_enabled(text: &str) -> Option<bool> {
    for raw_line in text.lines() {
        let line = strip_ini_comments(raw_line);
        if line.is_empty() {
            continue;
        }

        let Some((key, value)) = parse_ini_key_value(line) else {
            continue;
        };
        if !key.eq_ignore_ascii_case("ENABLED") {
            continue;
        }

        let value = value.trim_matches('"').trim_matches('\'').trim();
        if let Some(enabled) = parse_ini_bool(value) {
            return Some(enabled);
        }
    }

    None
}

fn parse_ufw_default_input_policy(text: &str) -> Option<String> {
    for raw_line in text.lines() {
        let line = strip_ini_comments(raw_line);
        if line.is_empty() {
            continue;
        }

        let Some((key, value)) = parse_ini_key_value(line) else {
            continue;
        };
        if !key.eq_ignore_ascii_case("DEFAULT_INPUT_POLICY") {
            continue;
        }

        let policy = value.trim_matches('"').trim_matches('\'').trim();
        if policy.is_empty() {
            continue;
        }

        return Some(policy.to_ascii_uppercase());
    }

    None
}

fn parse_unattended_upgrades_enabled(text: &str) -> Option<bool> {
    parse_apt_periodic_bool(text, APT_PERIODIC_UNATTENDED_UPGRADE_KEY)
}

fn parse_package_lists_auto_update_enabled(text: &str) -> Option<bool> {
    parse_apt_periodic_bool(text, APT_PERIODIC_UPDATE_PACKAGE_LISTS_KEY)
}

fn parse_apt_periodic_bool(text: &str, key: &str) -> Option<bool> {
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

fn strip_apt_comments(line: &str) -> &str {
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

fn scan_grub_hardening(context: &HostContext) -> Vec<Finding> {
    let grub_paths = ["boot/grub/grub.cfg", "boot/grub2/grub.cfg"];

    for relative in &grub_paths {
        let Some(path) = resolve_existing_path(&context.root, relative) else {
            continue;
        };

        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };

        let lower = text.to_ascii_lowercase();
        if lower.contains("password_pbkdf2")
            || lower.contains("password")
            || lower.contains("--unrestricted")
        {
            return Vec::new();
        }

        return vec![host_finding(
            "host.grub_password_missing",
            Severity::Medium,
            &path,
            HostFindingText {
                title: t!("finding.host.grub_password_missing.title").into_owned(),
                description: t!(
                    "finding.host.grub_password_missing.description",
                    path = path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.grub_password_missing.why").into_owned(),
                how_to_fix: t!("finding.host.grub_password_missing.fix").into_owned(),
            },
            BTreeMap::from([(String::from("path"), path.display().to_string())]),
        )];
    }

    Vec::new()
}

fn scan_shadow_hardening(context: &HostContext) -> Vec<Finding> {
    let Some(path) = resolve_existing_path(&context.root, "etc/shadow") else {
        return Vec::new();
    };

    let mut findings = Vec::new();

    if let Ok(metadata) = fs::metadata(&path) {
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 > 0o040 {
            findings.push(host_finding(
                "host.shadow_permissions_weak",
                Severity::Medium,
                &path,
                HostFindingText {
                    title: t!("finding.host.shadow_permissions_weak.title").into_owned(),
                    description: t!(
                        "finding.host.shadow_permissions_weak.description",
                        path = path.display().to_string(),
                        mode = format_permissions(mode)
                    )
                    .into_owned(),
                    why_risky: t!("finding.host.shadow_permissions_weak.why").into_owned(),
                    how_to_fix: t!("finding.host.shadow_permissions_weak.fix").into_owned(),
                },
                BTreeMap::from([
                    (String::from("path"), path.display().to_string()),
                    (String::from("mode"), format_permissions(mode)),
                ]),
            ));
        }
    }

    let Ok(text) = fs::read_to_string(&path) else {
        return findings;
    };

    let mut weak_hash_algorithm = None;
    let mut empty_password_found = false;

    for line in text.lines() {
        let stripped = line.trim();
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = stripped.split(':').collect();
        if parts.len() < 2 {
            continue;
        }

        let hash = parts[1];
        if hash.is_empty() {
            empty_password_found = true;
            continue;
        }

        if hash.starts_with("*") || hash.starts_with("!") {
            continue;
        }

        if hash.starts_with("$1$") && weak_hash_algorithm.is_none() {
            weak_hash_algorithm = Some("MD5");
        } else if hash.starts_with("$5$") && weak_hash_algorithm.is_none() {
            weak_hash_algorithm = Some("SHA-256");
        } else if hash.starts_with("$6$") || hash.starts_with("$y$") || hash.starts_with("$2") {
            continue;
        } else if weak_hash_algorithm.is_none() {
            weak_hash_algorithm = Some("unknown/legacy");
        }
    }

    if empty_password_found {
        findings.push(host_finding(
            "host.shadow_empty_password",
            Severity::Critical,
            &path,
            HostFindingText {
                title: t!("finding.host.shadow_empty_password.title").into_owned(),
                description: t!(
                    "finding.host.shadow_empty_password.description",
                    path = path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.shadow_empty_password.why").into_owned(),
                how_to_fix: t!("finding.host.shadow_empty_password.fix").into_owned(),
            },
            BTreeMap::from([(String::from("path"), path.display().to_string())]),
        ));
    }

    if let Some(algorithm) = weak_hash_algorithm {
        findings.push(host_finding(
            "host.shadow_weak_hash",
            Severity::High,
            &path,
            HostFindingText {
                title: t!("finding.host.shadow_weak_hash.title").into_owned(),
                description: t!(
                    "finding.host.shadow_weak_hash.description",
                    path = path.display().to_string(),
                    algorithm = algorithm
                )
                .into_owned(),
                why_risky: t!("finding.host.shadow_weak_hash.why").into_owned(),
                how_to_fix: t!("finding.host.shadow_weak_hash.fix").into_owned(),
            },
            BTreeMap::from([
                (String::from("path"), path.display().to_string()),
                (String::from("algorithm"), algorithm.to_owned()),
            ]),
        ));
    }

    findings
}

fn scan_tmp_hardening(context: &HostContext) -> Vec<Finding> {
    let mut findings = Vec::new();

    let mounts_path = context.root.join("proc/mounts");
    let Ok(text) = fs::read_to_string(&mounts_path) else {
        return findings;
    };

    let mut tmp_found = false;
    let mut tmp_flags = Vec::new();

    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        if parts[1] == "/tmp" {
            tmp_found = true;
            tmp_flags = parts[3].split(',').map(str::to_owned).collect();
            break;
        }
    }

    if !tmp_found {
        findings.push(host_finding(
            "host.tmp_not_tmpfs",
            Severity::Low,
            &context.root.join("proc/mounts"),
            HostFindingText {
                title: t!("finding.host.tmp_not_tmpfs.title").into_owned(),
                description: t!("finding.host.tmp_not_tmpfs.description").into_owned(),
                why_risky: t!("finding.host.tmp_not_tmpfs.why").into_owned(),
                how_to_fix: t!("finding.host.tmp_not_tmpfs.fix").into_owned(),
            },
            BTreeMap::new(),
        ));
        return findings;
    }

    let required_flags = ["noexec", "nosuid", "nodev"];
    let missing: Vec<String> = required_flags
        .iter()
        .filter(|flag| !tmp_flags.iter().any(|f| f == **flag))
        .map(|s| (*s).to_owned())
        .collect();

    if !missing.is_empty() {
        findings.push(host_finding(
            "host.tmp_tmpfs_flags_missing",
            Severity::Low,
            &context.root.join("proc/mounts"),
            HostFindingText {
                title: t!("finding.host.tmp_tmpfs_flags_missing.title").into_owned(),
                description: t!(
                    "finding.host.tmp_tmpfs_flags_missing.description",
                    flags = missing.join(", ")
                )
                .into_owned(),
                why_risky: t!("finding.host.tmp_tmpfs_flags_missing.why").into_owned(),
                how_to_fix: t!("finding.host.tmp_tmpfs_flags_missing.fix").into_owned(),
            },
            BTreeMap::from([(String::from("flags"), missing.join(", "))]),
        ));
    }

    findings
}

fn scan_defensive_controls(context: &HostContext, runtime: &HostRuntimeInfo) -> Vec<Finding> {
    match runtime.fail2ban {
        DefensiveControlStatus::Enabled => Vec::new(),
        DefensiveControlStatus::Installed => vec![host_finding(
            "host.fail2ban_not_enabled",
            Severity::Medium,
            &context.root,
            HostFindingText {
                title: t!("finding.host.fail2ban_not_enabled.title").into_owned(),
                description: t!(
                    "finding.host.fail2ban_not_enabled.description",
                    path = context.root.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.fail2ban_not_enabled.why").into_owned(),
                how_to_fix: t!("finding.host.fail2ban_not_enabled.fix").into_owned(),
            },
            BTreeMap::from([
                (String::from("path"), context.root.display().to_string()),
                (String::from("control"), String::from("fail2ban")),
            ]),
        )],
        DefensiveControlStatus::NotDetected => vec![host_finding(
            "host.defensive_controls_missing",
            Severity::Low,
            &context.root,
            HostFindingText {
                title: t!("finding.host.defensive_controls_missing.title").into_owned(),
                description: t!(
                    "finding.host.defensive_controls_missing.description",
                    path = context.root.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.defensive_controls_missing.why").into_owned(),
                how_to_fix: t!("finding.host.defensive_controls_missing.fix").into_owned(),
            },
            BTreeMap::from([
                (String::from("path"), context.root.display().to_string()),
                (String::from("checked_controls"), String::from("fail2ban")),
            ]),
        )],
    }
}

fn resolve_existing_path(root: &Path, relative: &str) -> Option<PathBuf> {
    let path = root.join(relative);
    path.exists().then_some(path)
}

fn detect_defensive_control(
    root: &Path,
    install_markers: &[&str],
    enabled_markers: &[&str],
) -> DefensiveControlStatus {
    if enabled_markers
        .iter()
        .any(|marker| resolve_existing_path(root, marker).is_some())
    {
        DefensiveControlStatus::Enabled
    } else if install_markers
        .iter()
        .any(|marker| resolve_existing_path(root, marker).is_some())
    {
        DefensiveControlStatus::Installed
    } else {
        DefensiveControlStatus::NotDetected
    }
}

fn collect_defensive_controls_snapshot(root: &Path) -> DefensiveControlsSnapshot {
    let mut snapshot = DefensiveControlsSnapshot {
        fail2ban_status: detect_defensive_control(
            root,
            &FAIL2BAN_INSTALL_MARKERS,
            &FAIL2BAN_ENABLED_MARKERS,
        ),
        fail2ban_jails: count_enabled_fail2ban_jails(root),
        ..DefensiveControlsSnapshot::default()
    };

    if !is_live_root(root) {
        return snapshot;
    }

    if let Some(live) = collect_fail2ban_live_summary() {
        snapshot.fail2ban_status = DefensiveControlStatus::Enabled;
        if live.jails.is_some() {
            snapshot.fail2ban_jails = live.jails;
        }
        snapshot.fail2ban_banned_ips = live.banned_ips;
    }

    snapshot
}

fn count_enabled_fail2ban_jails(root: &Path) -> Option<usize> {
    let mut parser = Fail2BanJailParser::default();
    let mut parsed_any_file = false;

    for path in fail2ban_jail_config_paths(root) {
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        parsed_any_file = true;
        parser.apply(&text);
    }

    parsed_any_file.then(|| parser.enabled_jail_count())
}

fn fail2ban_jail_config_paths(root: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    paths.push(root.join("etc/fail2ban/jail.conf"));
    paths.extend(sorted_fail2ban_dir_entries(
        root,
        "etc/fail2ban/jail.d",
        "conf",
    ));
    paths.push(root.join("etc/fail2ban/jail.local"));
    paths.extend(sorted_fail2ban_dir_entries(
        root,
        "etc/fail2ban/jail.d",
        "local",
    ));

    paths
}

fn sorted_fail2ban_dir_entries(root: &Path, relative_dir: &str, extension: &str) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(root.join(relative_dir)) else {
        return Vec::new();
    };

    let mut paths = entries
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some(extension))
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

#[derive(Debug, Default)]
struct Fail2BanJailParser {
    default_enabled: bool,
    sections: BTreeMap<String, Option<bool>>,
}

impl Fail2BanJailParser {
    fn apply(&mut self, text: &str) {
        let mut current_section: Option<String> = None;

        for raw_line in text.lines() {
            let line = strip_ini_comments(raw_line);
            if line.is_empty() {
                continue;
            }

            if let Some(section) = parse_ini_section(line) {
                current_section = Some(section.clone());
                if !is_special_fail2ban_section(&section) {
                    self.sections.entry(section).or_insert(None);
                }
                continue;
            }

            let Some(section) = current_section.as_deref() else {
                continue;
            };
            let Some((key, value)) = parse_ini_key_value(line) else {
                continue;
            };
            if !key.eq_ignore_ascii_case("enabled") {
                continue;
            }
            let Some(enabled) = parse_ini_bool(value) else {
                continue;
            };

            if section.eq_ignore_ascii_case("DEFAULT") {
                self.default_enabled = enabled;
            } else if !is_special_fail2ban_section(section) {
                self.sections.insert(section.to_owned(), Some(enabled));
            }
        }
    }

    fn enabled_jail_count(&self) -> usize {
        self.sections
            .values()
            .filter(|enabled| enabled.unwrap_or(self.default_enabled))
            .count()
    }
}

fn strip_ini_comments(line: &str) -> &str {
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

fn parse_ini_section(line: &str) -> Option<String> {
    let trimmed = line.trim();
    trimmed
        .strip_prefix('[')?
        .strip_suffix(']')
        .map(str::trim)
        .filter(|section| !section.is_empty())
        .map(str::to_owned)
}

fn parse_ini_key_value(line: &str) -> Option<(&str, &str)> {
    let (key, value) = line.split_once('=')?;
    Some((key.trim(), value.trim()))
}

fn parse_ini_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn is_special_fail2ban_section(section: &str) -> bool {
    section.eq_ignore_ascii_case("DEFAULT") || section.eq_ignore_ascii_case("INCLUDES")
}

fn collect_fail2ban_live_summary() -> Option<Fail2BanLiveSummary> {
    try_command(&["fail2ban-client", "ping"])?;

    let status_output = try_command(&["fail2ban-client", "status"]);
    let Some(status_output) = status_output else {
        return Some(Fail2BanLiveSummary::default());
    };

    let jails = parse_fail2ban_jails(&status_output);
    let mut total_banned = 0usize;
    let mut parsed_any_banned = jails.is_empty();

    for jail in &jails {
        let Some(jail_output) = try_command(&["fail2ban-client", "status", jail.as_str()]) else {
            continue;
        };
        let Some(currently_banned) = parse_fail2ban_currently_banned(&jail_output) else {
            continue;
        };
        total_banned += currently_banned;
        parsed_any_banned = true;
    }

    Some(Fail2BanLiveSummary {
        jails: Some(jails.len()),
        banned_ips: parsed_any_banned.then_some(total_banned),
    })
}

fn parse_fail2ban_jails(output: &str) -> Vec<String> {
    output
        .lines()
        .find_map(|line| line.split_once("Jail list:"))
        .map(|(_, list)| {
            list.split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn parse_fail2ban_currently_banned(output: &str) -> Option<usize> {
    parse_labeled_usize(output, "Currently banned:")
}

fn parse_labeled_usize(output: &str, label: &str) -> Option<usize> {
    output.lines().find_map(|line| {
        let (_, value) = line.trim().split_once(label)?;
        value.trim().parse::<usize>().ok()
    })
}

fn read_hostname(root: &Path) -> Option<String> {
    let path = resolve_existing_path(root, "etc/hostname")?;
    let content = fs::read_to_string(path).ok()?;
    let trimmed = content.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

fn read_uptime(root: &Path) -> Option<String> {
    let path = resolve_existing_path(root, "proc/uptime")?;
    let content = fs::read_to_string(path).ok()?;
    let seconds = parse_uptime_seconds(&content)?;
    Some(format_uptime(seconds))
}

fn read_load_average(root: &Path) -> Option<String> {
    let path = resolve_existing_path(root, "proc/loadavg")?;
    let content = fs::read_to_string(path).ok()?;
    parse_load_average(&content)
}

fn parse_uptime_seconds(content: &str) -> Option<u64> {
    let seconds = content.split_whitespace().next()?.parse::<f64>().ok()?;
    Some(seconds.floor() as u64)
}

fn format_uptime(seconds: u64) -> String {
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let minutes = (seconds % 3_600) / 60;

    if days > 0 {
        format!("{days}d {hours}h {minutes}m")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else {
        format!("{minutes}m")
    }
}

fn parse_load_average(content: &str) -> Option<String> {
    let parts = content
        .split_whitespace()
        .take(3)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    (parts.len() == 3).then(|| parts.join(" "))
}

fn discover_docker_version(root: &Path) -> Option<String> {
    if !is_live_root(root) {
        return None;
    }

    try_command(&["docker", "version", "--format", "{{.Server.Version}}"])
        .filter(|value| !value.contains("{{"))
        .or_else(|| {
            try_command(&["docker", "--version"])
                .and_then(|output| parse_docker_version_output(&output))
        })
        .or_else(|| {
            try_command(&["dockerd", "--version"])
                .and_then(|output| parse_docker_version_output(&output))
        })
}

fn try_command(command: &[&str]) -> Option<String> {
    let (program, args) = command.split_first()?;
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    (!stdout.is_empty()).then_some(stdout)
}

fn parse_docker_version_output(output: &str) -> Option<String> {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some((_, rest)) = trimmed.split_once("Docker version ") {
        let version = rest.split(',').next()?.trim();
        return (!version.is_empty()).then(|| version.to_owned());
    }

    Some(trimmed.to_owned())
}

fn is_live_root(root: &Path) -> bool {
    root.canonicalize()
        .map(|path| path == Path::new("/"))
        .unwrap_or(false)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SshdSetting {
    value: String,
    source: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SshdConfigResult {
    settings: BTreeMap<String, SshdSetting>,
    listen_addresses: Vec<SshdSetting>,
}

fn parse_sshd_config(root: &Path, path: &Path) -> std::io::Result<SshdConfigResult> {
    let mut result = SshdConfigResult {
        settings: BTreeMap::new(),
        listen_addresses: Vec::new(),
    };
    let mut visited = HashSet::new();
    parse_sshd_config_file(root, path, &mut result, &mut visited)?;
    Ok(result)
}

fn parse_sshd_config_file(
    root: &Path,
    path: &Path,
    result: &mut SshdConfigResult,
    visited: &mut HashSet<PathBuf>,
) -> std::io::Result<()> {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    if !visited.insert(canonical) {
        return Ok(());
    }

    let content = fs::read_to_string(path)?;
    let include_base_dir = root.join("etc/ssh");

    for raw_line in content.lines() {
        let stripped = raw_line.split('#').next().unwrap_or_default().trim();
        if stripped.is_empty() {
            continue;
        }

        let mut parts = stripped.split_whitespace();
        let Some(key) = parts.next() else {
            continue;
        };

        if key.eq_ignore_ascii_case("match") {
            break;
        }

        if key.eq_ignore_ascii_case("include") {
            for pattern in parts {
                let pattern = pattern.trim_matches('"').trim_matches('\'').trim();
                if pattern.is_empty() {
                    continue;
                }

                let resolved = if pattern.starts_with('/') {
                    root.join(pattern.trim_start_matches('/'))
                } else {
                    include_base_dir.join(pattern)
                };

                let mut matches = Vec::new();
                if let Some(pattern_text) = resolved.to_str()
                    && let Ok(paths) = glob(pattern_text)
                {
                    for entry in paths.flatten() {
                        matches.push(entry);
                    }
                }
                matches.sort();

                for include_path in matches {
                    let _ = parse_sshd_config_file(root, &include_path, result, visited);
                }
            }

            continue;
        }

        let Some(value) = parts.next() else {
            continue;
        };

        let setting = SshdSetting {
            value: value.to_ascii_lowercase(),
            source: path.to_path_buf(),
        };

        let key_lower = key.to_ascii_lowercase();
        if key_lower == "listenaddress" {
            result.listen_addresses.push(setting);
        } else {
            result.settings.entry(key_lower).or_insert(setting);
        }
    }

    Ok(())
}

fn daemon_hosts_include_public_tcp(document: &JsonValue) -> bool {
    let Some(hosts) = document.get("hosts") else {
        return false;
    };

    match hosts {
        JsonValue::Array(items) => items.iter().any(host_is_public_tcp),
        JsonValue::String(_) => host_is_public_tcp(hosts),
        _ => false,
    }
}

fn daemon_tlsverify_enabled(document: &JsonValue) -> bool {
    document
        .get("tlsverify")
        .and_then(JsonValue::as_bool)
        .unwrap_or(false)
}

fn docker_daemon_iptables_disabled(document: &JsonValue) -> bool {
    document.get("iptables").and_then(JsonValue::as_bool) == Some(false)
}

fn docker_daemon_setting_state(document: &JsonValue, key: &str) -> String {
    match document.get(key).and_then(JsonValue::as_bool) {
        Some(true) => String::from("true"),
        Some(false) => String::from("false"),
        None => String::from("missing"),
    }
}

fn docker_daemon_userns_remapped(document: &JsonValue) -> bool {
    document
        .get("userns-remap")
        .and_then(|v| v.as_str())
        .is_some_and(|v| !v.is_empty())
}

fn docker_daemon_live_restore_enabled(document: &JsonValue) -> bool {
    document.get("live-restore").and_then(JsonValue::as_bool) == Some(true)
}

fn docker_daemon_log_driver_configured(document: &JsonValue) -> bool {
    document
        .get("log-driver")
        .and_then(|v| v.as_str())
        .is_some_and(|v| !v.is_empty())
}

fn docker_daemon_default_ulimits_configured(document: &JsonValue) -> bool {
    document
        .get("default-ulimits")
        .and_then(JsonValue::as_object)
        .is_some_and(|obj| !obj.is_empty())
}

fn host_is_public_tcp(value: &JsonValue) -> bool {
    let Some(host) = value.as_str() else {
        return false;
    };

    if !host.starts_with("tcp://") {
        return false;
    }

    !(host.contains("127.0.0.1") || host.contains("localhost") || host.contains("[::1]"))
}

fn format_permissions(mode: u32) -> String {
    format!("0o{:03o}", mode)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn temp_host_root(name: &str) -> PathBuf {
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

    fn write_file(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("parent should be created");
        }
        fs::write(path, content).expect("file should be written");
    }

    #[test]
    fn host_scanner_detects_insecure_ssh_and_docker_settings() {
        let root = temp_host_root("insecure");
        write_file(
            &root.join(SSH_CONFIG_PATH),
            concat!(
                "PermitRootLogin yes\n",
                "PasswordAuthentication yes\n",
                "PermitEmptyPasswords yes\n",
                "PubkeyAuthentication no\n",
                "PermitUserEnvironment yes\n"
            ),
        );
        write_file(
            &root.join(DOCKER_DAEMON_CONFIG_PATH),
            r#"{"hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2375"], "tlsverify": false, "iptables": false}"#,
        );
        write_file(&root.join(DOCKER_SOCKET_PATH), "socket");
        fs::set_permissions(
            root.join(DOCKER_SOCKET_PATH),
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
                "host.no_firewall_detected",
                "host.docker_userns_remap_missing",
                "host.docker_live_restore_disabled",
                "host.docker_log_driver_missing",
                "host.docker_default_ulimits_missing",
                "host.kernel.module_signing_not_enforced",
                "host.mac_framework_missing",
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
        write_file(&root.join("etc/hostname"), "hardened\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(findings.is_empty());

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_detects_selinux_permissive() {
        let root = temp_host_root("selinux-permissive");
        write_file(
            &root.join("etc/selinux/config"),
            "SELINUX=permissive\nSELINUXTYPE=targeted\n",
        );
        write_file(&root.join("etc/hostname"), "selinux-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.selinux_permissive")
        );

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_detects_apparmor_complain_mode() {
        let root = temp_host_root("apparmor-complain");
        write_file(
            &root.join("sys/kernel/security/apparmor/profiles"),
            concat!(
                "/usr/sbin/dnsmasq (enforce)\n",
                "/usr/bin/dockerd (complain)\n",
                "/usr/sbin/nginx (enforce)\n",
                "/usr/sbin/sshd (enforce)\n",
            ),
        );
        write_file(&root.join("etc/hostname"), "apparmor-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.apparmor_complain_mode")
        );

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_detects_missing_systemd_hardening() {
        let root = temp_host_root("systemd-hardening");
        write_file(
            &root.join("lib/systemd/system/sshd.service"),
            "[Service]\nExecStart=/usr/sbin/sshd\n",
        );
        write_file(&root.join("etc/hostname"), "systemd-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.systemd_hardening_missing"
                    && finding.evidence.get("service") == Some(&String::from("sshd.service")))
        );

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_detects_missing_proc_hidepid() {
        let root = temp_host_root("proc-hidepid");
        write_file(&root.join("proc/mounts"), "ext4 / ext4 rw,relatime 0 0\n");
        write_file(&root.join("etc/hostname"), "hidepid-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.proc_hidepid_missing")
        );

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_reports_mac_missing_when_neither_present() {
        let root = temp_host_root("mac-missing");
        write_file(&root.join("etc/hostname"), "mac-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.mac_framework_missing")
        );

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_detects_missing_mount_flags() {
        let root = temp_host_root("mount-flags");
        write_file(
            &root.join("proc/mounts"),
            concat!(
                "tmpfs /tmp tmpfs rw,relatime 0 0\n",
                "ext4 /home ext4 rw,noexec,nosuid,nodev,relatime 0 0\n",
                "ext4 /var ext4 rw,noexec,nosuid,nodev,relatime 0 0\n",
            ),
        );
        write_file(&root.join("etc/hostname"), "mount-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        let mount_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.id == "host.mount_flags_missing")
            .collect();
        assert_eq!(mount_findings.len(), 1);
        assert_eq!(
            mount_findings[0].evidence.get("mount_point"),
            Some(&String::from("/tmp"))
        );

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_skips_hardened_snapshot() {
        let root = temp_host_root("hardened");
        write_file(
            &root.join(SSH_CONFIG_PATH),
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
            &root.join(DOCKER_DAEMON_CONFIG_PATH),
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
        write_file(&root.join(DOCKER_SOCKET_PATH), "socket");
        fs::set_permissions(
            root.join(DOCKER_SOCKET_PATH),
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
    fn host_scanner_detects_missing_grub_password() {
        let root = temp_host_root("grub-missing");
        write_file(
            &root.join("boot/grub/grub.cfg"),
            "set timeout=5\nmenuentry 'Linux' {\nlinux /vmlinuz\n}\n",
        );
        write_file(&root.join("etc/hostname"), "grub-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.grub_password_missing")
        );

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_skips_grub_when_password_present() {
        let root = temp_host_root("grub-password");
        write_file(
            &root.join("boot/grub2/grub.cfg"),
            "set superusers=\"admin\"\npassword_pbkdf2 admin grub.pbkdf2...\n",
        );
        write_file(&root.join("etc/hostname"), "grub-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .all(|finding| finding.id != "host.grub_password_missing")
        );

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_detects_weak_shadow_permissions() {
        let root = temp_host_root("shadow-perms");
        write_file(
            &root.join("etc/shadow"),
            "root:$6$rounds=5000$salt$hash:0:0:root:/root:/bin/bash\n",
        );
        fs::set_permissions(root.join("etc/shadow"), fs::Permissions::from_mode(0o644))
            .expect("permissions should be set");
        write_file(&root.join("etc/hostname"), "shadow-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.shadow_permissions_weak")
        );
        assert!(
            findings
                .iter()
                .all(|finding| finding.id != "host.shadow_weak_hash")
        );

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_detects_weak_shadow_hashes() {
        let root = temp_host_root("shadow-hash");
        write_file(
            &root.join("etc/shadow"),
            "root:$1$salt$hash:0:0:root:/root:/bin/bash\n",
        );
        fs::set_permissions(root.join("etc/shadow"), fs::Permissions::from_mode(0o640))
            .expect("permissions should be set");
        write_file(&root.join("etc/hostname"), "shadow-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.shadow_weak_hash")
        );

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_detects_empty_shadow_passwords() {
        let root = temp_host_root("shadow-empty");
        write_file(&root.join("etc/shadow"), "root::0:0:root:/root:/bin/bash\n");
        fs::set_permissions(root.join("etc/shadow"), fs::Permissions::from_mode(0o640))
            .expect("permissions should be set");
        write_file(&root.join("etc/hostname"), "shadow-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.shadow_empty_password")
        );

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_detects_modules_disabled_not_set() {
        let root = temp_host_root("modules-disabled");
        write_file(&root.join("proc/sys/kernel/modules_disabled"), "0\n");
        write_file(&root.join("etc/hostname"), "modules-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.kernel.modules_disabled_not_set")
        );

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_detects_tmp_not_tmpfs() {
        let root = temp_host_root("tmp-not-tmpfs");
        write_file(&root.join("proc/mounts"), "ext4 / ext4 rw,relatime 0 0\n");
        write_file(&root.join("etc/hostname"), "tmp-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.tmp_not_tmpfs")
        );

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_detects_tmp_missing_flags() {
        let root = temp_host_root("tmp-flags");
        write_file(
            &root.join("proc/mounts"),
            concat!(
                "tmpfs /tmp tmpfs rw,nosuid,nodev,relatime 0 0\n",
                "ext4 / ext4 rw,relatime 0 0\n",
            ),
        );
        write_file(&root.join("etc/hostname"), "tmp-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.tmp_tmpfs_flags_missing")
        );
        assert_eq!(
            findings
                .iter()
                .find(|f| f.id == "host.tmp_tmpfs_flags_missing")
                .and_then(|f| f.evidence.get("flags")),
            Some(&String::from("noexec"))
        );

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn public_docker_tcp_with_tlsverify_avoids_extra_tls_finding() {
        let root = temp_host_root("docker-tlsverify");
        write_file(
            &root.join(DOCKER_DAEMON_CONFIG_PATH),
            r#"{"hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2376"], "tlsverify": true}"#,
        );

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.docker_daemon_tcp_public")
        );
        assert!(
            findings
                .iter()
                .all(|finding| finding.id != "host.docker_daemon_tcp_no_tlsverify")
        );

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn collects_runtime_info_from_host_snapshot() {
        let root = temp_host_root("runtime");
        write_file(&root.join("etc/hostname"), "home-server\n");
        write_file(
            &root.join("etc/fail2ban/jail.local"),
            "[sshd]\nenabled = true\n",
        );
        write_file(
            &root.join("etc/systemd/system/multi-user.target.wants/fail2ban.service"),
            "enabled\n",
        );
        write_file(&root.join("proc/uptime"), "1221720.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.42 0.31 0.27 1/100 1234\n");

        let info = collect_host_runtime_info(&HostContext { root: root.clone() });

        assert_eq!(info.hostname.as_deref(), Some("home-server"));
        assert_eq!(info.uptime.as_deref(), Some("14d 3h 22m"));
        assert_eq!(info.load_average.as_deref(), Some("0.42 0.31 0.27"));
        assert!(info.docker_version.is_none());
        assert_eq!(info.fail2ban, DefensiveControlStatus::Enabled);
        assert_eq!(info.fail2ban_jails, Some(1));
        assert_eq!(info.fail2ban_banned_ips, None);

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn counts_enabled_fail2ban_jails_from_config_precedence_order() {
        let root = temp_host_root("fail2ban-config-order");
        write_file(
            &root.join("etc/fail2ban/jail.conf"),
            concat!(
                "[DEFAULT]\n",
                "enabled = false\n",
                "\n",
                "[sshd]\n",
                "enabled = false\n",
                "\n",
                "[nginx-http-auth]\n",
                "enabled = false\n"
            ),
        );
        write_file(
            &root.join("etc/fail2ban/jail.d/10-enable-sshd.local"),
            "[sshd]\nenabled = true ; keep sshd enabled\n",
        );
        write_file(
            &root.join("etc/fail2ban/jail.d/20-enable-default.local"),
            "[DEFAULT]\nenabled = true\n",
        );
        write_file(
            &root.join("etc/fail2ban/jail.d/30-disable-nginx.local"),
            "[nginx-http-auth]\nenabled = false\n",
        );

        let count = count_enabled_fail2ban_jails(&root);

        assert_eq!(count, Some(1));

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn defensive_control_missing_finding_is_cleared_when_fail2ban_is_enabled() {
        let root = temp_host_root("fail2ban-enabled");
        write_file(
            &root.join("etc/systemd/system/multi-user.target.wants/fail2ban.service"),
            "enabled\n",
        );

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .all(|finding| finding.id != "host.defensive_controls_missing")
        );

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn reports_fail2ban_when_installed_but_not_enabled() {
        let root = temp_host_root("fail2ban-installed");
        write_file(&root.join("etc/fail2ban/jail.local"), "[DEFAULT]\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.fail2ban_not_enabled")
        );
        assert!(
            findings
                .iter()
                .all(|finding| finding.id != "host.defensive_controls_missing")
        );

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn parses_docker_version_output() {
        assert_eq!(
            super::parse_docker_version_output("Docker version 26.1.4, build deadbeef\n"),
            Some(String::from("26.1.4"))
        );
        assert_eq!(
            super::parse_docker_version_output("27.0.3\n"),
            Some(String::from("27.0.3"))
        );
    }

    #[test]
    fn parse_sshd_config_stops_at_match_block() {
        let root = temp_host_root("match-block");
        let path = root.join(SSH_CONFIG_PATH);
        write_file(
            &path,
            concat!(
                "PermitRootLogin no\n",
                "Match User backup\n",
                "  PermitRootLogin yes\n"
            ),
        );

        let parsed = parse_sshd_config(&root, &path).expect("config should parse");

        assert_eq!(
            parsed
                .settings
                .get("permitrootlogin")
                .map(|setting| setting.value.as_str()),
            Some("no")
        );

        assert_eq!(
            parsed
                .settings
                .get("permitrootlogin")
                .map(|setting| setting.source.as_path()),
            Some(path.as_path())
        );

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn reports_ssh_x11_forwarding_when_enabled() {
        let root = temp_host_root("ssh-x11-forwarding");
        write_file(&root.join(SSH_CONFIG_PATH), "X11Forwarding yes\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.ssh_x11_forwarding_enabled")
        );

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn parse_sshd_config_honors_include_globs_and_tracks_effective_source() {
        let root = temp_host_root("sshd-include-abs");
        let config_path = root.join(SSH_CONFIG_PATH);
        let include_path = root.join("etc/ssh/sshd_config.d/10-extra.conf");

        write_file(
            &config_path,
            concat!(
                "Include /etc/ssh/sshd_config.d/*.conf\n",
                "PermitRootLogin yes\n"
            ),
        );
        write_file(&include_path, "PermitRootLogin no\n");

        let parsed = parse_sshd_config(&root, &config_path).expect("config should parse");

        let permit_root = parsed
            .settings
            .get("permitrootlogin")
            .expect("permitrootlogin should be set");
        assert_eq!(permit_root.value, "no");
        assert_eq!(permit_root.source, include_path);

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn parse_sshd_config_include_does_not_override_existing_setting() {
        let root = temp_host_root("sshd-include-rel");
        let config_path = root.join(SSH_CONFIG_PATH);
        let include_path = root.join("etc/ssh/sshd_config.d/99-override.conf");

        write_file(
            &config_path,
            concat!("PermitRootLogin no\n", "Include sshd_config.d/*.conf\n"),
        );
        write_file(&include_path, "PermitRootLogin yes\n");

        let parsed = parse_sshd_config(&root, &config_path).expect("config should parse");

        let permit_root = parsed
            .settings
            .get("permitrootlogin")
            .expect("permitrootlogin should be set");
        assert_eq!(permit_root.value, "no");
        assert_eq!(permit_root.source, config_path);

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn parse_sshd_config_avoids_include_cycles() {
        let root = temp_host_root("sshd-include-cycle");
        let config_path = root.join(SSH_CONFIG_PATH);
        let include_path = root.join("etc/ssh/sshd_config.d/cycle.conf");

        write_file(
            &config_path,
            concat!(
                "PermitRootLogin no\n",
                "Include /etc/ssh/sshd_config.d/cycle.conf\n"
            ),
        );
        write_file(
            &include_path,
            concat!("Include /etc/ssh/sshd_config\n", "PermitRootLogin yes\n"),
        );

        let parsed = parse_sshd_config(&root, &config_path).expect("config should parse");

        let permit_root = parsed
            .settings
            .get("permitrootlogin")
            .expect("permitrootlogin should be set");
        assert_eq!(permit_root.value, "no");
        assert_eq!(permit_root.source, config_path);

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn parse_sshd_config_relative_includes_resolve_from_etc_ssh() {
        let root = temp_host_root("sshd-include-relative-base");
        let config_path = root.join(SSH_CONFIG_PATH);
        let first_include = root.join("etc/ssh/sshd_config.d/10-chain.conf");
        let chained_include = root.join("etc/ssh/extra.conf");

        write_file(&config_path, "Include /etc/ssh/sshd_config.d/*.conf\n");
        write_file(
            &first_include,
            concat!("Include extra.conf\n", "PermitRootLogin yes\n"),
        );
        write_file(&chained_include, "PermitRootLogin no\n");

        let parsed = parse_sshd_config(&root, &config_path).expect("config should parse");

        let permit_root = parsed
            .settings
            .get("permitrootlogin")
            .expect("permitrootlogin should be set");
        assert_eq!(permit_root.value, "no");
        assert_eq!(permit_root.source, chained_include);

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn parses_fail2ban_status_output() {
        let jails = parse_fail2ban_jails(concat!(
            "Status\n",
            "|- Number of jail:  2\n",
            "`- Jail list: sshd, nginx-http-auth\n"
        ));

        assert_eq!(
            jails,
            vec![String::from("sshd"), String::from("nginx-http-auth")]
        );
        assert_eq!(
            parse_fail2ban_currently_banned(concat!(
                "Status for the jail: sshd\n",
                "|- Filter\n",
                "|  |- Currently failed: 0\n",
                "`- Actions\n",
                "   |- Currently banned: 3\n"
            )),
            Some(3)
        );
    }

    #[test]
    fn reports_ufw_when_installed_but_disabled() {
        let root = temp_host_root("ufw-disabled");
        write_file(&root.join("usr/sbin/ufw"), "");
        write_file(&root.join(UFW_CONFIG_PATH), "ENABLED=no\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.ufw_installed_but_disabled")
        );

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn reports_ufw_default_input_policy_accept() {
        let root = temp_host_root("ufw-default-accept");
        write_file(&root.join("usr/sbin/ufw"), "");
        write_file(&root.join(UFW_CONFIG_PATH), "ENABLED=yes\n");
        write_file(
            &root.join(UFW_DEFAULT_POLICY_PATH),
            "DEFAULT_INPUT_POLICY=\"ACCEPT\"\n",
        );

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.ufw_default_input_policy_accept")
        );

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn does_not_report_ufw_default_policy_when_drop() {
        let root = temp_host_root("ufw-default-drop");
        write_file(&root.join("usr/sbin/ufw"), "");
        write_file(&root.join(UFW_CONFIG_PATH), "ENABLED=yes\n");
        write_file(
            &root.join(UFW_DEFAULT_POLICY_PATH),
            "DEFAULT_INPUT_POLICY=\"DROP\"\n",
        );

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .all(|finding| finding.id != "host.ufw_default_input_policy_accept")
        );

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn does_not_report_ufw_when_enabled() {
        let root = temp_host_root("ufw-enabled");
        write_file(&root.join(UFW_CONFIG_PATH), "ENABLED=yes\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .all(|finding| finding.id != "host.ufw_installed_but_disabled")
        );

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn reports_unattended_upgrades_when_explicitly_disabled() {
        let root = temp_host_root("apt-auto-upgrades-disabled");
        write_file(
            &root.join(APT_AUTO_UPGRADES_CONFIG_PATH),
            concat!(
                "APT::Periodic::Update-Package-Lists \"1\";\n",
                "APT::Periodic::Unattended-Upgrade \"0\";\n"
            ),
        );

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.apt_unattended_upgrades_disabled")
        );

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn reports_package_list_auto_updates_when_disabled() {
        let root = temp_host_root("apt-package-lists-disabled");
        write_file(
            &root.join(APT_AUTO_UPGRADES_CONFIG_PATH),
            concat!(
                "APT::Periodic::Update-Package-Lists \"0\";\n",
                "APT::Periodic::Unattended-Upgrade \"1\";\n"
            ),
        );

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.apt_package_lists_auto_update_disabled")
        );
        assert!(
            findings
                .iter()
                .all(|finding| finding.id != "host.apt_unattended_upgrades_disabled")
        );

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn unattended_upgrades_parser_handles_common_formats() {
        assert_eq!(
            parse_unattended_upgrades_enabled("APT::Periodic::Unattended-Upgrade \"1\";"),
            Some(true)
        );
        assert_eq!(
            parse_unattended_upgrades_enabled("APT::Periodic::Unattended-Upgrade \"0\";"),
            Some(false)
        );
        assert_eq!(
            parse_unattended_upgrades_enabled("APT::Periodic::Unattended-Upgrade 1;"),
            Some(true)
        );
        assert_eq!(
            parse_unattended_upgrades_enabled("APT::Periodic::Update-Package-Lists \"1\";"),
            None
        );
        assert_eq!(
            parse_package_lists_auto_update_enabled("APT::Periodic::Update-Package-Lists \"1\";"),
            Some(true)
        );
        assert_eq!(
            parse_package_lists_auto_update_enabled("APT::Periodic::Update-Package-Lists 0;"),
            Some(false)
        );
    }

    #[test]
    fn ufw_default_input_policy_parser_handles_common_formats() {
        assert_eq!(
            parse_ufw_default_input_policy("DEFAULT_INPUT_POLICY=\"ACCEPT\""),
            Some(String::from("ACCEPT"))
        );
        assert_eq!(
            parse_ufw_default_input_policy("DEFAULT_INPUT_POLICY='DROP'"),
            Some(String::from("DROP"))
        );
        assert_eq!(
            parse_ufw_default_input_policy("DEFAULT_INPUT_POLICY="),
            None
        );
    }

    #[test]
    fn host_scanner_detects_weak_ssh_algorithms() {
        let root = temp_host_root("ssh-weak-algos");
        write_file(
            &root.join(SSH_CONFIG_PATH),
            concat!(
                "KexAlgorithms diffie-hellman-group1-sha1,curve25519-sha256\n",
                "MACs hmac-md5,hmac-sha2-512-etm@openssh.com\n",
                "Ciphers arcfour,aes256-gcm@openssh.com\n",
            ),
        );

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.ssh_weak_kex")
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.ssh_weak_macs")
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.ssh_weak_ciphers")
        );

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_detects_firewalld_disabled() {
        let root = temp_host_root("firewalld-disabled");
        write_file(&root.join("usr/bin/firewall-cmd"), "");
        write_file(
            &root.join("etc/firewalld/firewalld.conf"),
            "DefaultZone=public\n",
        );
        write_file(&root.join("etc/hostname"), "firewalld-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.firewalld_installed_but_disabled")
        );

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_detects_firewalld_trusted_zone() {
        let root = temp_host_root("firewalld-trusted");
        write_file(&root.join("usr/bin/firewall-cmd"), "");
        write_file(
            &root.join("etc/systemd/system/multi-user.target.wants/firewalld.service"),
            "",
        );
        write_file(
            &root.join("etc/firewalld/firewalld.conf"),
            "DefaultZone=trusted\n",
        );
        write_file(&root.join("etc/hostname"), "firewalld-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.firewalld_default_zone_trusted")
        );

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_detects_nftables_empty() {
        let root = temp_host_root("nftables-empty");
        write_file(&root.join("etc/nftables.conf"), "");
        write_file(&root.join("etc/hostname"), "nftables-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.nftables_installed_no_rules")
        );

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

    #[test]
    fn host_scanner_detects_dnf_automatic_disabled() {
        let root = temp_host_root("dnf-automatic-disabled");
        write_file(
            &root.join("etc/dnf/automatic.conf"),
            "[commands]\napply_updates = no\n",
        );
        write_file(&root.join("etc/hostname"), "dnf-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.dnf_automatic_disabled")
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.dnf_automatic_timer_disabled")
        );

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn host_scanner_detects_yum_cron_disabled() {
        let root = temp_host_root("yum-cron-disabled");
        write_file(
            &root.join("etc/yum/yum-cron.conf"),
            "[commands]\napply_updates = no\n",
        );
        write_file(&root.join("etc/hostname"), "yum-test\n");
        write_file(&root.join("proc/uptime"), "60.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.10 0.20 0.30 1/100 123\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.yum_cron_disabled")
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "host.yum_cron_service_disabled")
        );

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn parse_ini_bool_in_section_handles_sections() {
        let text = concat!(
            "[commands]\n",
            "apply_updates = yes\n",
            "\n",
            "[email]\n",
            "apply_updates = no\n",
        );
        assert_eq!(
            parse_ini_bool_in_section(text, "commands", "apply_updates"),
            Some(true)
        );
        assert_eq!(
            parse_ini_bool_in_section(text, "email", "apply_updates"),
            Some(false)
        );
        assert_eq!(parse_ini_bool_in_section(text, "commands", "missing"), None);
    }
}
