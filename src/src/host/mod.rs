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
const DOCKER_DAEMON_CONFIG_PATH: &str = "etc/docker/daemon.json";
const DOCKER_SOCKET_PATH: &str = "var/run/docker.sock";
const UFW_CONFIG_PATH: &str = "etc/ufw/ufw.conf";
const UFW_DEFAULT_POLICY_PATH: &str = "etc/default/ufw";
const UFW_INSTALL_MARKERS: [&str; 3] = ["etc/ufw/ufw.conf", "usr/sbin/ufw", "usr/bin/ufw"];
const APT_AUTO_UPGRADES_CONFIG_PATH: &str = "etc/apt/apt.conf.d/20auto-upgrades";
const APT_PERIODIC_UNATTENDED_UPGRADE_KEY: &str = "APT::Periodic::Unattended-Upgrade";
const APT_PERIODIC_UPDATE_PACKAGE_LISTS_KEY: &str = "APT::Periodic::Update-Package-Lists";
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
        findings.extend(scan_firewall_hardening(context));
        findings.extend(scan_package_update_hardening(context));
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

    findings
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

    findings
}

fn scan_firewall_hardening(context: &HostContext) -> Vec<Finding> {
    if !detect_ufw_installed(&context.root) {
        return Vec::new();
    }

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

fn scan_package_update_hardening(context: &HostContext) -> Vec<Finding> {
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
            r#"{"hosts": ["unix:///var/run/docker.sock", "tcp://127.0.0.1:2375"]}"#,
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

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

        assert!(findings.is_empty());

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
}
