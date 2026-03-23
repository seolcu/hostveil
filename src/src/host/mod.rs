use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::Value as JsonValue;

use crate::domain::{Axis, Finding, RemediationKind, Scope, Severity, Source};

const SSH_CONFIG_PATH: &str = "etc/ssh/sshd_config";
const DOCKER_DAEMON_CONFIG_PATH: &str = "etc/docker/daemon.json";
const DOCKER_SOCKET_PATH: &str = "var/run/docker.sock";

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
        findings
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

fn resolve_existing_path(root: &Path, relative: &str) -> Option<PathBuf> {
    let path = root.join(relative);
    path.exists().then_some(path)
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
