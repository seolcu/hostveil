use std::collections::BTreeMap;

use crate::compose::{ComposeProject, VolumeMount};
use crate::domain::{Axis, Finding, Severity};

use super::{ServiceFindingText, service_finding};

const ROOT_USERS: [&str; 3] = ["root", "0", "0:0"];
const SENSITIVE_EXACT_PATHS: [&str; 2] = ["/", "/var/run/docker.sock"];
const SENSITIVE_PREFIXES: [&str; 2] = ["/etc", "/home"];
const SAFE_ETC_PATHS: [&str; 2] = ["/etc/localtime", "/etc/timezone"];

pub fn scan_permission_risk(project: &ComposeProject) -> Vec<Finding> {
    let mut findings = Vec::new();

    for service in project.services.values() {
        if service.privileged {
            findings.push(service_finding(
                "permissions.privileged",
                Axis::ExcessivePermissions,
                Severity::Critical,
                &service.name,
                ServiceFindingText {
                    title: t!("finding.permissions.privileged.title").into_owned(),
                    description: t!(
                        "finding.permissions.privileged.description",
                        service = service.name.as_str()
                    )
                    .into_owned(),
                    why_risky: t!("finding.permissions.privileged.why").into_owned(),
                    how_to_fix: t!("finding.permissions.privileged.fix").into_owned(),
                },
                BTreeMap::new(),
            ));
        }

        match service.user.as_deref() {
            None => findings.push(service_finding(
                "permissions.implicit_root",
                Axis::ExcessivePermissions,
                Severity::Medium,
                &service.name,
                ServiceFindingText {
                    title: t!("finding.permissions.implicit_root.title").into_owned(),
                    description: t!(
                        "finding.permissions.implicit_root.description",
                        service = service.name.as_str()
                    )
                    .into_owned(),
                    why_risky: t!("finding.permissions.implicit_root.why").into_owned(),
                    how_to_fix: t!("finding.permissions.implicit_root.fix").into_owned(),
                },
                BTreeMap::new(),
            )),
            Some(user) if ROOT_USERS.contains(&user.trim().to_lowercase().as_str()) => {
                findings.push(service_finding(
                    "permissions.root_user",
                    Axis::ExcessivePermissions,
                    Severity::High,
                    &service.name,
                    ServiceFindingText {
                        title: t!("finding.permissions.root.title").into_owned(),
                        description: t!(
                            "finding.permissions.root.description",
                            service = service.name.as_str()
                        )
                        .into_owned(),
                        why_risky: t!("finding.permissions.root.why").into_owned(),
                        how_to_fix: t!("finding.permissions.root.fix").into_owned(),
                    },
                    BTreeMap::from([(String::from("user"), user.to_owned())]),
                ));
            }
            Some(_) => {}
        }

        if service.network_mode.as_deref() == Some("host") {
            findings.push(service_finding(
                "permissions.host_network",
                Axis::ExcessivePermissions,
                Severity::High,
                &service.name,
                ServiceFindingText {
                    title: t!("finding.permissions.host_network.title").into_owned(),
                    description: t!(
                        "finding.permissions.host_network.description",
                        service = service.name.as_str()
                    )
                    .into_owned(),
                    why_risky: t!("finding.permissions.host_network.why").into_owned(),
                    how_to_fix: t!("finding.permissions.host_network.fix").into_owned(),
                },
                BTreeMap::new(),
            ));
        }

        for mount in &service.volumes {
            let Some(sensitive_path) = classify_sensitive_mount(mount) else {
                continue;
            };

            findings.push(service_finding(
                "permissions.sensitive_mount",
                Axis::ExcessivePermissions,
                mount_severity(sensitive_path),
                &service.name,
                ServiceFindingText {
                    title: t!("finding.permissions.sensitive_mount.title").into_owned(),
                    description: t!(
                        "finding.permissions.sensitive_mount.description",
                        service = service.name.as_str(),
                        path = sensitive_path
                    )
                    .into_owned(),
                    why_risky: t!("finding.permissions.sensitive_mount.why").into_owned(),
                    how_to_fix: t!("finding.permissions.sensitive_mount.fix").into_owned(),
                },
                BTreeMap::from([(String::from("path"), sensitive_path.to_owned())]),
            ));
        }
    }

    findings
}

pub fn classify_sensitive_mount(mount: &VolumeMount) -> Option<&str> {
    if mount.mount_type != "bind" {
        return None;
    }

    let source = mount.source.as_deref()?;
    let normalized = if source.trim_end_matches('/').is_empty() {
        "/"
    } else {
        source.trim_end_matches('/')
    };

    if SAFE_ETC_PATHS.contains(&normalized) {
        return None;
    }
    if SENSITIVE_EXACT_PATHS.contains(&normalized) {
        return Some(normalized);
    }
    if SENSITIVE_PREFIXES
        .iter()
        .any(|prefix| normalized == *prefix || normalized.starts_with(&format!("{prefix}/")))
    {
        return Some(normalized);
    }

    None
}

fn mount_severity(path: &str) -> Severity {
    if SENSITIVE_EXACT_PATHS.contains(&path) {
        Severity::Critical
    } else {
        Severity::High
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use crate::compose::ComposeParser;

    use super::*;

    fn fixture() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../proto/tests/fixtures/rules/permissions-risk.yml")
            .canonicalize()
            .expect("fixture should exist")
    }

    #[test]
    fn detects_expected_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture()).expect("project should parse");

        let findings = scan_permission_risk(&project);

        assert_eq!(
            findings
                .iter()
                .map(|finding| (
                    finding.id.as_str(),
                    finding.related_service.as_deref().unwrap_or_default()
                ))
                .collect::<Vec<_>>(),
            vec![
                ("permissions.privileged", "privileged"),
                ("permissions.root_user", "root_user"),
                ("permissions.implicit_root", "implicit_root"),
                ("permissions.host_network", "hostnet"),
                ("permissions.sensitive_mount", "docker_socket"),
                ("permissions.sensitive_mount", "host_home"),
            ]
        );
        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.severity)
                .collect::<Vec<_>>(),
            vec![
                Severity::Critical,
                Severity::High,
                Severity::Medium,
                Severity::High,
                Severity::Critical,
                Severity::High,
            ]
        );
    }

    #[test]
    fn skips_non_sensitive_relative_mounts() {
        let project =
            ComposeParser::parse_path_without_override(fixture()).expect("project should parse");

        let findings = scan_permission_risk(&project);

        assert!(
            findings
                .iter()
                .all(|finding| finding.related_service.as_deref() != Some("safe"))
        );
    }
}
