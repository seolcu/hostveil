use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value as JsonValue;

use crate::domain::{Axis, Finding, HostRuntimeInfo, RemediationKind, Scope, Severity, Source};

const SSH_CONFIG_PATH: &str = "etc/ssh/sshd_config";
const DOCKER_DAEMON_CONFIG_PATH: &str = "etc/docker/daemon.json";
const DOCKER_SOCKET_PATH: &str = "var/run/docker.sock";
const FAIL2BAN_MARKERS: [&str; 6] = [
    "etc/fail2ban",
    "usr/bin/fail2ban-client",
    "usr/bin/fail2ban-server",
    "usr/sbin/fail2ban-server",
    "lib/systemd/system/fail2ban.service",
    "usr/lib/systemd/system/fail2ban.service",
];
const CROWDSEC_MARKERS: [&str; 6] = [
    "etc/crowdsec",
    "usr/bin/crowdsec",
    "usr/bin/cscli",
    "usr/local/bin/cscli",
    "lib/systemd/system/crowdsec.service",
    "usr/lib/systemd/system/crowdsec.service",
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
        let mut findings = Vec::new();
        findings.extend(scan_ssh_hardening(context));
        findings.extend(scan_docker_host_exposure(context));
        findings.extend(scan_defensive_controls(context));
        findings
    }
}

pub fn collect_host_runtime_info(context: &HostContext) -> HostRuntimeInfo {
    HostRuntimeInfo {
        hostname: read_hostname(&context.root),
        docker_version: discover_docker_version(&context.root),
        uptime: read_uptime(&context.root),
        load_average: read_load_average(&context.root),
    }
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

    let Ok(settings) = parse_sshd_config(&config_path) else {
        return Vec::new();
    };

    let mut findings = Vec::new();

    if settings
        .get("permitrootlogin")
        .is_some_and(|value| value != "no")
    {
        let value = settings
            .get("permitrootlogin")
            .cloned()
            .unwrap_or_else(|| String::from("yes"));
        findings.push(host_finding(
            "host.ssh_root_login_enabled",
            Severity::High,
            &config_path,
            HostFindingText {
                title: t!("finding.host.ssh_root_login.title").into_owned(),
                description: t!(
                    "finding.host.ssh_root_login.description",
                    path = config_path.display().to_string(),
                    value = value.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.host.ssh_root_login.why").into_owned(),
                how_to_fix: t!("finding.host.ssh_root_login.fix").into_owned(),
            },
            BTreeMap::from([
                (String::from("path"), config_path.display().to_string()),
                (String::from("value"), value),
            ]),
        ));
    }

    if settings
        .get("passwordauthentication")
        .is_some_and(|value| value == "yes")
    {
        findings.push(host_finding(
            "host.ssh_password_auth_enabled",
            Severity::High,
            &config_path,
            HostFindingText {
                title: t!("finding.host.ssh_password_auth.title").into_owned(),
                description: t!(
                    "finding.host.ssh_password_auth.description",
                    path = config_path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.ssh_password_auth.why").into_owned(),
                how_to_fix: t!("finding.host.ssh_password_auth.fix").into_owned(),
            },
            BTreeMap::from([(String::from("path"), config_path.display().to_string())]),
        ));
    }

    if settings
        .get("permitemptypasswords")
        .is_some_and(|value| value == "yes")
    {
        findings.push(host_finding(
            "host.ssh_empty_passwords_enabled",
            Severity::Critical,
            &config_path,
            HostFindingText {
                title: t!("finding.host.ssh_empty_passwords.title").into_owned(),
                description: t!(
                    "finding.host.ssh_empty_passwords.description",
                    path = config_path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.ssh_empty_passwords.why").into_owned(),
                how_to_fix: t!("finding.host.ssh_empty_passwords.fix").into_owned(),
            },
            BTreeMap::from([(String::from("path"), config_path.display().to_string())]),
        ));
    }

    if settings
        .get("pubkeyauthentication")
        .is_some_and(|value| value == "no")
    {
        findings.push(host_finding(
            "host.ssh_pubkey_auth_disabled",
            Severity::Medium,
            &config_path,
            HostFindingText {
                title: t!("finding.host.ssh_pubkey_auth.title").into_owned(),
                description: t!(
                    "finding.host.ssh_pubkey_auth.description",
                    path = config_path.display().to_string()
                )
                .into_owned(),
                why_risky: t!("finding.host.ssh_pubkey_auth.why").into_owned(),
                how_to_fix: t!("finding.host.ssh_pubkey_auth.fix").into_owned(),
            },
            BTreeMap::from([(String::from("path"), config_path.display().to_string())]),
        ));
    }

    findings
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
        && daemon_hosts_include_public_tcp(&json)
    {
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
    }

    findings
}

fn scan_defensive_controls(context: &HostContext) -> Vec<Finding> {
    let fail2ban_present = has_any_marker(&context.root, &FAIL2BAN_MARKERS);
    let crowdsec_present = has_any_marker(&context.root, &CROWDSEC_MARKERS);

    if fail2ban_present || crowdsec_present {
        return Vec::new();
    }

    vec![host_finding(
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
            (
                String::from("checked_controls"),
                String::from("fail2ban,crowdsec"),
            ),
        ]),
    )]
}

fn resolve_existing_path(root: &Path, relative: &str) -> Option<PathBuf> {
    let path = root.join(relative);
    path.exists().then_some(path)
}

fn has_any_marker(root: &Path, markers: &[&str]) -> bool {
    markers
        .iter()
        .any(|marker| resolve_existing_path(root, marker).is_some())
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

fn parse_sshd_config(path: &Path) -> std::io::Result<BTreeMap<String, String>> {
    let mut settings = BTreeMap::new();
    let content = fs::read_to_string(path)?;

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
        let Some(value) = parts.next() else {
            continue;
        };

        settings.insert(key.to_ascii_lowercase(), value.to_ascii_lowercase());
    }

    Ok(settings)
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
                "PubkeyAuthentication no\n"
            ),
        );
        write_file(
            &root.join(DOCKER_DAEMON_CONFIG_PATH),
            r#"{"hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2375"]}"#,
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
                "host.docker_socket_world_writable",
                "host.docker_daemon_tcp_public",
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
                "PubkeyAuthentication yes\n"
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
    fn collects_runtime_info_from_host_snapshot() {
        let root = temp_host_root("runtime");
        write_file(&root.join("etc/hostname"), "home-server\n");
        write_file(&root.join("proc/uptime"), "1221720.00 0.00\n");
        write_file(&root.join("proc/loadavg"), "0.42 0.31 0.27 1/100 1234\n");

        let info = collect_host_runtime_info(&HostContext { root: root.clone() });

        assert_eq!(info.hostname.as_deref(), Some("home-server"));
        assert_eq!(info.uptime.as_deref(), Some("14d 3h 22m"));
        assert_eq!(info.load_average.as_deref(), Some("0.42 0.31 0.27"));
        assert!(info.docker_version.is_none());

        fs::remove_dir_all(root).expect("temp root should be removed");
    }

    #[test]
    fn defensive_control_finding_is_cleared_when_crowdsec_exists() {
        let root = temp_host_root("crowdsec-present");
        write_file(&root.join("etc/crowdsec/config.yaml"), "api:\n  server:\n");

        let findings = HostScanner.scan(&HostContext { root: root.clone() });

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

        let parsed = parse_sshd_config(&path).expect("config should parse");

        assert_eq!(parsed.get("permitrootlogin"), Some(&String::from("no")));

        fs::remove_dir_all(root).expect("temp root should be removed");
    }
}
