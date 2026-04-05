use std::collections::BTreeMap;
use std::fs;

use crate::compose::{ComposeProject, ComposeService};
use crate::domain::{Axis, Finding, Severity};

use super::exposure::is_public_port;
use super::{ServiceFindingText, service_finding};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServiceKind {
    Vaultwarden,
    Jellyfin,
    Gitea,
    Immich,
}

pub fn scan_service_aware_risk(project: &ComposeProject) -> Vec<Finding> {
    let mut findings = Vec::new();

    for service in project.services.values() {
        let Some(kind) = detect_service_kind(service) else {
            continue;
        };

        match kind {
            ServiceKind::Vaultwarden => findings.extend(scan_vaultwarden_risk(service)),
            ServiceKind::Jellyfin => findings.extend(scan_jellyfin_risk(service)),
            ServiceKind::Gitea => findings.extend(scan_gitea_risk(service)),
            ServiceKind::Immich => findings.extend(scan_immich_risk(project, service)),
        }
    }

    findings
}

fn detect_service_kind(service: &ComposeService) -> Option<ServiceKind> {
    let haystack = format!(
        "{} {}",
        service.name,
        service.image.as_deref().unwrap_or_default()
    )
    .to_lowercase();

    if haystack.contains("vaultwarden") {
        Some(ServiceKind::Vaultwarden)
    } else if haystack.contains("jellyfin") {
        Some(ServiceKind::Jellyfin)
    } else if haystack.contains("gitea") {
        Some(ServiceKind::Gitea)
    } else if service.name.contains("immich-server") || haystack.contains("immich-server") {
        Some(ServiceKind::Immich)
    } else {
        None
    }
}

fn scan_vaultwarden_risk(service: &ComposeService) -> Vec<Finding> {
    let mut findings = Vec::new();
    let publicly_exposed = service.ports.iter().any(is_public_port);

    if env_truthy(service, "SIGNUPS_ALLOWED") {
        findings.push(service_finding(
            "service.vaultwarden.signups_enabled",
            Axis::UnnecessaryExposure,
            Severity::Medium,
            &service.name,
            ServiceFindingText {
                title: t!("finding.vaultwarden.signups_enabled.title").into_owned(),
                description: t!(
                    "finding.vaultwarden.signups_enabled.description",
                    service = service.name.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.vaultwarden.signups_enabled.why").into_owned(),
                how_to_fix: t!("finding.vaultwarden.signups_enabled.fix").into_owned(),
            },
            BTreeMap::from([(String::from("variable"), String::from("SIGNUPS_ALLOWED"))]),
        ));
    }

    if publicly_exposed && admin_token_configured(service) {
        findings.push(service_finding(
            "service.vaultwarden.admin_surface_public",
            Axis::UnnecessaryExposure,
            Severity::High,
            &service.name,
            ServiceFindingText {
                title: t!("finding.vaultwarden.admin_surface_public.title").into_owned(),
                description: t!(
                    "finding.vaultwarden.admin_surface_public.description",
                    service = service.name.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.vaultwarden.admin_surface_public.why").into_owned(),
                how_to_fix: t!("finding.vaultwarden.admin_surface_public.fix").into_owned(),
            },
            BTreeMap::from([
                (String::from("variable"), String::from("ADMIN_TOKEN")),
                (
                    String::from("public_port_count"),
                    service.ports.len().to_string(),
                ),
            ]),
        ));
    }

    if publicly_exposed
        && let Some(domain) = env_value(service, "DOMAIN")
        && domain.starts_with("http://")
    {
        findings.push(service_finding(
            "service.vaultwarden.insecure_domain",
            Axis::UnnecessaryExposure,
            Severity::High,
            &service.name,
            ServiceFindingText {
                title: t!("finding.vaultwarden.insecure_domain.title").into_owned(),
                description: t!(
                    "finding.vaultwarden.insecure_domain.description",
                    service = service.name.as_str(),
                    domain = domain
                )
                .into_owned(),
                why_risky: t!("finding.vaultwarden.insecure_domain.why").into_owned(),
                how_to_fix: t!("finding.vaultwarden.insecure_domain.fix").into_owned(),
            },
            BTreeMap::from([(String::from("domain"), domain.to_owned())]),
        ));
    }

    findings
}

fn scan_jellyfin_risk(service: &ComposeService) -> Vec<Finding> {
    let mut findings = Vec::new();
    let publicly_exposed = service.ports.iter().any(is_public_port);

    if publicly_exposed
        && let Some(url) = env_value(service, "JELLYFIN_PublishedServerUrl")
        && url.starts_with("http://")
    {
        findings.push(service_finding(
            "service.jellyfin.insecure_published_url",
            Axis::UnnecessaryExposure,
            Severity::High,
            &service.name,
            ServiceFindingText {
                title: t!("finding.jellyfin.insecure_published_url.title").into_owned(),
                description: t!(
                    "finding.jellyfin.insecure_published_url.description",
                    service = service.name.as_str(),
                    url = url
                )
                .into_owned(),
                why_risky: t!("finding.jellyfin.insecure_published_url.why").into_owned(),
                how_to_fix: t!("finding.jellyfin.insecure_published_url.fix").into_owned(),
            },
            BTreeMap::from([(String::from("url"), url.to_owned())]),
        ));
    }

    if let Some(port) = service.ports.iter().find(|port| {
        port.container_port == "7359" && port.protocol == "udp" && is_public_port(port)
    }) {
        findings.push(service_finding(
            "service.jellyfin.discovery_public",
            Axis::UnnecessaryExposure,
            Severity::Medium,
            &service.name,
            ServiceFindingText {
                title: t!("finding.jellyfin.discovery_public.title").into_owned(),
                description: t!(
                    "finding.jellyfin.discovery_public.description",
                    service = service.name.as_str(),
                    port = port.raw.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.jellyfin.discovery_public.why").into_owned(),
                how_to_fix: t!("finding.jellyfin.discovery_public.fix").into_owned(),
            },
            BTreeMap::from([(String::from("port"), port.raw.clone())]),
        ));
    }

    if let Some(path) = writable_media_mount(service) {
        findings.push(service_finding(
            "service.jellyfin.media_mount_writable",
            Axis::ExcessivePermissions,
            Severity::Low,
            &service.name,
            ServiceFindingText {
                title: t!("finding.jellyfin.media_mount_writable.title").into_owned(),
                description: t!(
                    "finding.jellyfin.media_mount_writable.description",
                    service = service.name.as_str(),
                    path = path
                )
                .into_owned(),
                why_risky: t!("finding.jellyfin.media_mount_writable.why").into_owned(),
                how_to_fix: t!("finding.jellyfin.media_mount_writable.fix").into_owned(),
            },
            BTreeMap::from([(String::from("path"), path.to_owned())]),
        ));
    }

    findings
}

fn scan_gitea_risk(service: &ComposeService) -> Vec<Finding> {
    let mut findings = Vec::new();
    let web_public = service.ports.iter().any(|port| {
        port.container_port == "3000" && port.protocol == "tcp" && is_public_port(port)
    });
    let ssh_public = service
        .ports
        .iter()
        .find(|port| port.container_port == "22" && port.protocol == "tcp" && is_public_port(port));

    if web_public && ssh_public.is_some() {
        findings.push(service_finding(
            "service.gitea.web_and_ssh_public",
            Axis::UnnecessaryExposure,
            Severity::High,
            &service.name,
            ServiceFindingText {
                title: t!("finding.gitea.web_and_ssh_public.title").into_owned(),
                description: t!(
                    "finding.gitea.web_and_ssh_public.description",
                    service = service.name.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.gitea.web_and_ssh_public.why").into_owned(),
                how_to_fix: t!("finding.gitea.web_and_ssh_public.fix").into_owned(),
            },
            BTreeMap::from([
                (String::from("web_port"), String::from("3000")),
                (String::from("ssh_port"), String::from("22")),
            ]),
        ));
    }

    if let Some(port) = ssh_public {
        findings.push(service_finding(
            "service.gitea.ssh_published_public",
            Axis::UnnecessaryExposure,
            Severity::Medium,
            &service.name,
            ServiceFindingText {
                title: t!("finding.gitea.ssh_published_public.title").into_owned(),
                description: t!(
                    "finding.gitea.ssh_published_public.description",
                    service = service.name.as_str(),
                    port = port.raw.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.gitea.ssh_published_public.why").into_owned(),
                how_to_fix: t!("finding.gitea.ssh_published_public.fix").into_owned(),
            },
            BTreeMap::from([(String::from("port"), port.raw.clone())]),
        ));
    }

    let security_keys = inline_env_keys(
        service,
        &[
            "GITEA__security__SECRET_KEY",
            "GITEA__security__INTERNAL_TOKEN",
        ],
    );
    if !security_keys.is_empty() {
        findings.push(service_finding(
            "service.gitea.inline_security_secrets",
            Axis::SensitiveData,
            Severity::High,
            &service.name,
            ServiceFindingText {
                title: t!("finding.gitea.inline_security_secrets.title").into_owned(),
                description: t!(
                    "finding.gitea.inline_security_secrets.description",
                    service = service.name.as_str(),
                    variables = security_keys.join(", ")
                )
                .into_owned(),
                why_risky: t!("finding.gitea.inline_security_secrets.why").into_owned(),
                how_to_fix: t!("finding.gitea.inline_security_secrets.fix").into_owned(),
            },
            BTreeMap::from([(String::from("variables"), security_keys.join(","))]),
        ));
    }

    findings
}

fn scan_immich_risk(project: &ComposeProject, service: &ComposeService) -> Vec<Finding> {
    let mut findings = Vec::new();
    let shared_secret_env_files = shared_secret_env_files(project, "immich");

    if !shared_secret_env_files.is_empty() {
        findings.push(service_finding(
            "service.immich.shared_secret_env_file",
            Axis::SensitiveData,
            Severity::High,
            &service.name,
            ServiceFindingText {
                title: t!("finding.immich.shared_secret_env_file.title").into_owned(),
                description: t!(
                    "finding.immich.shared_secret_env_file.description",
                    service = service.name.as_str(),
                    env_file = shared_secret_env_files.join(", ")
                )
                .into_owned(),
                why_risky: t!("finding.immich.shared_secret_env_file.why").into_owned(),
                how_to_fix: t!("finding.immich.shared_secret_env_file.fix").into_owned(),
            },
            BTreeMap::from([(String::from("env_files"), shared_secret_env_files.join(","))]),
        ));
    }

    if immich_default_db_password(project) {
        findings.push(service_finding(
            "service.immich.default_db_password",
            Axis::SensitiveData,
            Severity::Critical,
            &service.name,
            ServiceFindingText {
                title: t!("finding.immich.default_db_password.title").into_owned(),
                description: t!(
                    "finding.immich.default_db_password.description",
                    service = service.name.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.immich.default_db_password.why").into_owned(),
                how_to_fix: t!("finding.immich.default_db_password.fix").into_owned(),
            },
            BTreeMap::from([(String::from("variable"), String::from("DB_PASSWORD"))]),
        ));
    }

    findings
}

fn env_truthy(service: &ComposeService, key: &str) -> bool {
    env_value(service, key).is_some_and(|value| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "true" | "yes" | "on" | "1"
        )
    })
}

fn env_value<'a>(service: &'a ComposeService, key: &str) -> Option<&'a str> {
    service
        .environment
        .get(key)
        .and_then(|value| value.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn admin_token_configured(service: &ComposeService) -> bool {
    env_value(service, "ADMIN_TOKEN").is_some() || env_value(service, "ADMIN_TOKEN_FILE").is_some()
}

fn writable_media_mount(service: &ComposeService) -> Option<&str> {
    service.volumes.iter().find_map(|mount| {
        let target = mount.target.as_deref()?;
        if mount.mount_type == "bind"
            && target.starts_with("/media")
            && mount.mode.as_deref() != Some("ro")
        {
            Some(target)
        } else {
            None
        }
    })
}

fn inline_env_keys(service: &ComposeService, keys: &[&str]) -> Vec<String> {
    keys.iter()
        .filter_map(|key| env_value(service, key).map(|_| (*key).to_owned()))
        .collect()
}

fn shared_secret_env_files(project: &ComposeProject, service_prefix: &str) -> Vec<String> {
    let mut usages = BTreeMap::<String, usize>::new();

    for service in project.services.values() {
        if !service.name.starts_with(service_prefix) {
            continue;
        }

        for env_file in &service.env_files {
            let values = env_file_values(project, env_file);
            if values
                .keys()
                .any(|key| key.contains("PASSWORD") || key.contains("SECRET"))
            {
                *usages.entry(env_file.clone()).or_default() += 1;
            }
        }
    }

    usages
        .into_iter()
        .filter_map(|(env_file, count)| (count > 1).then_some(env_file))
        .collect()
}

fn immich_default_db_password(project: &ComposeProject) -> bool {
    let mut values = BTreeMap::<String, String>::new();

    for service in project.services.values() {
        if service.name.starts_with("immich-") {
            for env_file in &service.env_files {
                values.extend(env_file_values(project, env_file));
            }
        }

        for (key, value) in &service.environment {
            if let Some(value) = value.as_deref() {
                values.insert(key.clone(), value.trim().to_owned());
            }
        }
    }

    values
        .get("DB_PASSWORD")
        .is_some_and(|value| value == "postgres")
        || values
            .get("POSTGRES_PASSWORD")
            .is_some_and(|value| value == "postgres")
}

fn env_file_values(project: &ComposeProject, env_file: &str) -> BTreeMap<String, String> {
    let path = project.working_dir.join(env_file);
    let Ok(text) = fs::read_to_string(path) else {
        return BTreeMap::new();
    };

    let mut values = BTreeMap::new();
    for line in text.lines() {
        let stripped = line.trim();
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }

        let Some((key, value)) = stripped.split_once('=') else {
            continue;
        };
        values.insert(key.trim().to_owned(), value.trim().to_owned());
    }

    values
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use crate::compose::ComposeParser;

    use super::scan_service_aware_risk;

    fn fixture(service: &str, path: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/services")
            .join(service)
            .join(path)
            .canonicalize()
            .expect("fixture should exist")
    }

    #[test]
    fn vaultwarden_baseline_avoids_service_specific_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("vaultwarden", "baseline.yml"))
                .expect("project should parse");

        let findings = scan_service_aware_risk(&project);

        assert!(findings.is_empty());
    }

    #[test]
    fn vaultwarden_vulnerable_fixture_triggers_service_specific_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("vaultwarden", "vulnerable.yml"))
                .expect("project should parse");

        let findings = scan_service_aware_risk(&project);

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "service.vaultwarden.signups_enabled",
                "service.vaultwarden.admin_surface_public",
                "service.vaultwarden.insecure_domain",
            ]
        );
    }

    #[test]
    fn jellyfin_baseline_avoids_service_specific_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("jellyfin", "baseline.yml"))
                .expect("project should parse");

        let findings = scan_service_aware_risk(&project);

        assert!(findings.is_empty());
    }

    #[test]
    fn jellyfin_vulnerable_fixture_triggers_service_specific_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("jellyfin", "vulnerable.yml"))
                .expect("project should parse");

        let findings = scan_service_aware_risk(&project);

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "service.jellyfin.insecure_published_url",
                "service.jellyfin.discovery_public",
                "service.jellyfin.media_mount_writable",
            ]
        );
    }

    #[test]
    fn gitea_baseline_avoids_service_specific_findings() {
        let project = ComposeParser::parse_path_without_override(fixture("gitea", "baseline.yml"))
            .expect("project should parse");

        let findings = scan_service_aware_risk(&project);

        assert!(findings.is_empty());
    }

    #[test]
    fn gitea_vulnerable_fixture_triggers_service_specific_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("gitea", "vulnerable.yml"))
                .expect("project should parse");

        let findings = scan_service_aware_risk(&project);

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "service.gitea.web_and_ssh_public",
                "service.gitea.ssh_published_public",
                "service.gitea.inline_security_secrets",
            ]
        );
    }

    #[test]
    fn immich_baseline_avoids_service_specific_findings() {
        let project = ComposeParser::parse_path_without_override(fixture("immich", "baseline.yml"))
            .expect("project should parse");

        let findings = scan_service_aware_risk(&project);

        assert!(findings.is_empty());
    }

    #[test]
    fn immich_vulnerable_fixture_triggers_service_specific_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("immich", "vulnerable.yml"))
                .expect("project should parse");

        let findings = scan_service_aware_risk(&project);

        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "service.immich.shared_secret_env_file",
                "service.immich.default_db_password",
            ]
        );
    }
}
