use std::collections::BTreeMap;

use crate::compose::{ComposeProject, ComposeService};
use crate::domain::{Axis, Finding, Severity};

use super::exposure::is_public_port;
use super::{ServiceFindingText, service_finding};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServiceKind {
    Vaultwarden,
}

pub fn scan_service_aware_risk(project: &ComposeProject) -> Vec<Finding> {
    let mut findings = Vec::new();

    for service in project.services.values() {
        let Some(kind) = detect_service_kind(service) else {
            continue;
        };

        match kind {
            ServiceKind::Vaultwarden => findings.extend(scan_vaultwarden_risk(service)),
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

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use crate::compose::ComposeParser;

    use super::scan_service_aware_risk;

    fn fixture(path: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/services/vaultwarden")
            .join(path)
            .canonicalize()
            .expect("fixture should exist")
    }

    #[test]
    fn vaultwarden_baseline_avoids_service_specific_findings() {
        let project = ComposeParser::parse_path_without_override(fixture("baseline.yml"))
            .expect("project should parse");

        let findings = scan_service_aware_risk(&project);

        assert!(findings.is_empty());
    }

    #[test]
    fn vaultwarden_vulnerable_fixture_triggers_service_specific_findings() {
        let project = ComposeParser::parse_path_without_override(fixture("vulnerable.yml"))
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
}
