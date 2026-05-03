use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;

use serde_json::Value as JsonValue;

use super::{
    HostContext, HostFindingText, format_permissions, host_finding, is_live_root,
    resolve_existing_path, try_command,
};
use crate::domain::{Finding, Severity};

pub(crate) const DOCKER_DAEMON_CONFIG_PATH: &str = "etc/docker/daemon.json";
pub(crate) const DOCKER_SOCKET_PATH: &str = "var/run/docker.sock";

pub fn scan_docker_host_exposure(context: &HostContext) -> Vec<Finding> {
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
}

pub fn scan_docker_daemon_hardening(context: &HostContext) -> Vec<Finding> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::HostScanner;
    use crate::host::tests::{temp_host_root, write_file};

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

        std::fs::remove_dir_all(root).expect("temp root should be removed");
    }
}
