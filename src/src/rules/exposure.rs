use std::collections::BTreeMap;

use crate::compose::{ComposeProject, PortBinding};
use crate::domain::{Axis, Finding, RemediationKind, Severity};

use super::{ServiceFindingText, service_finding, service_finding_with_remediation};

const ADMIN_SERVICE_HINTS: [&str; 5] = ["adminer", "pgadmin", "phpmyadmin", "portainer", "traefik"];
const REVERSE_PROXY_HINTS: [&str; 3] = ["vaultwarden", "gitea", "immich"];
const LOCAL_ONLY_HOSTS: [&str; 3] = ["127.0.0.1", "::1", "localhost"];

pub fn scan_exposure_risk(project: &ComposeProject) -> Vec<Finding> {
    let mut findings = Vec::new();

    for service in project.services.values() {
        let public_ports = service
            .ports
            .iter()
            .filter(|port| is_public_port(port))
            .collect::<Vec<_>>();
        if public_ports.is_empty() {
            continue;
        }

        let first_public = public_ports[0];
        findings.push(service_finding_with_remediation(
            "exposure.public_binding",
            Axis::UnnecessaryExposure,
            Severity::Medium,
            &service.name,
            ServiceFindingText {
                title: t!("finding.exposure.public_bind.title").into_owned(),
                description: t!(
                    "finding.exposure.public_bind.description",
                    service = service.name.as_str(),
                    port = first_public.raw.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.exposure.public_bind.why").into_owned(),
                how_to_fix: t!("finding.exposure.public_bind.fix").into_owned(),
            },
            BTreeMap::from([
                (String::from("port"), first_public.raw.clone()),
                (
                    String::from("host_ip"),
                    first_public
                        .host_ip
                        .clone()
                        .unwrap_or_else(|| String::from("0.0.0.0")),
                ),
                (
                    String::from("host_port"),
                    first_public.host_port.clone().unwrap_or_default(),
                ),
                (
                    String::from("container_port"),
                    first_public.container_port.clone(),
                ),
            ]),
            RemediationKind::Auto,
        ));

        if matches_known_service(
            &service.name,
            service.image.as_deref(),
            &ADMIN_SERVICE_HINTS,
        ) {
            findings.push(service_finding(
                "exposure.admin_interface_public",
                Axis::UnnecessaryExposure,
                Severity::Critical,
                &service.name,
                ServiceFindingText {
                    title: t!("finding.exposure.admin_public.title").into_owned(),
                    description: t!(
                        "finding.exposure.admin_public.description",
                        service = service.name.as_str(),
                        port = first_public.raw.as_str()
                    )
                    .into_owned(),
                    why_risky: t!("finding.exposure.admin_public.why").into_owned(),
                    how_to_fix: t!("finding.exposure.admin_public.fix").into_owned(),
                },
                BTreeMap::from([(String::from("port"), first_public.raw.clone())]),
            ));
        }

        if matches_known_service(
            &service.name,
            service.image.as_deref(),
            &REVERSE_PROXY_HINTS,
        ) {
            findings.push(service_finding(
                "exposure.reverse_proxy_expected",
                Axis::UnnecessaryExposure,
                Severity::High,
                &service.name,
                ServiceFindingText {
                    title: t!("finding.exposure.reverse_proxy.title").into_owned(),
                    description: t!(
                        "finding.exposure.reverse_proxy.description",
                        service = service.name.as_str(),
                        port = first_public.raw.as_str()
                    )
                    .into_owned(),
                    why_risky: t!("finding.exposure.reverse_proxy.why").into_owned(),
                    how_to_fix: t!("finding.exposure.reverse_proxy.fix").into_owned(),
                },
                BTreeMap::from([(String::from("port"), first_public.raw.clone())]),
            ));
        }
    }

    findings
}

pub fn is_public_port(port: &PortBinding) -> bool {
    if port
        .host_ip
        .as_deref()
        .is_some_and(|host| LOCAL_ONLY_HOSTS.contains(&host))
    {
        return false;
    }

    matches!(
        port.host_ip.as_deref(),
        None | Some("0.0.0.0") | Some("::") | Some("[::]")
    )
}

fn matches_known_service(service_name: &str, image: Option<&str>, hints: &[&str]) -> bool {
    let haystack = format!("{} {}", service_name, image.unwrap_or_default()).to_lowercase();
    hints.iter().any(|hint| haystack.contains(hint))
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use crate::compose::ComposeParser;

    use super::*;

    fn fixture() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../proto/tests/fixtures/rules/exposure-risk.yml")
            .canonicalize()
            .expect("fixture should exist")
    }

    #[test]
    fn detects_expected_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture()).expect("project should parse");

        let findings = scan_exposure_risk(&project);

        assert_eq!(
            findings
                .iter()
                .map(|finding| (
                    finding.id.as_str(),
                    finding.related_service.as_deref().unwrap_or_default()
                ))
                .collect::<Vec<_>>(),
            vec![
                ("exposure.public_binding", "jellyfin"),
                ("exposure.public_binding", "adminer"),
                ("exposure.admin_interface_public", "adminer"),
                ("exposure.public_binding", "vaultwarden"),
                ("exposure.reverse_proxy_expected", "vaultwarden"),
            ]
        );
    }

    #[test]
    fn skips_localhost_bindings() {
        let project =
            ComposeParser::parse_path_without_override(fixture()).expect("project should parse");

        let findings = scan_exposure_risk(&project);

        assert!(
            findings
                .iter()
                .all(|finding| finding.related_service.as_deref() != Some("redis"))
        );
    }

    #[test]
    fn marks_public_binding_as_safe_remediation() {
        let project =
            ComposeParser::parse_path_without_override(fixture()).expect("project should parse");
        let finding = scan_exposure_risk(&project)
            .into_iter()
            .find(|finding| finding.id == "exposure.public_binding")
            .expect("public binding finding should exist");
        assert_eq!(finding.remediation, crate::domain::RemediationKind::Auto);
    }

    #[test]
    fn is_public_port_matches_implicit_all_interfaces() {
        let port = crate::compose::model::PortBinding {
            raw: String::new(),
            host_ip: None,
            host_port: Some("8080".to_string()),
            container_port: "80".to_string(),
            protocol: "tcp".to_string(),
            short_syntax: false,
        };
        assert!(is_public_port(&port));
    }

    #[test]
    fn is_public_port_skips_localhost_ipv6() {
        let port = crate::compose::model::PortBinding {
            raw: String::new(),
            host_ip: Some("::1".to_string()),
            host_port: Some("8080".to_string()),
            container_port: "80".to_string(),
            protocol: "tcp".to_string(),
            short_syntax: false,
        };
        assert!(!is_public_port(&port));
    }

    #[test]
    fn is_public_port_matches_ipv6_wildcard() {
        let port = crate::compose::model::PortBinding {
            raw: String::new(),
            host_ip: Some("::".to_string()),
            host_port: Some("8080".to_string()),
            container_port: "80".to_string(),
            protocol: "tcp".to_string(),
            short_syntax: false,
        };
        assert!(is_public_port(&port));
    }

    #[test]
    fn admin_interface_hints_include_all_services() {
        let hints = crate::rules::exposure::ADMIN_SERVICE_HINTS;
        assert!(hints.contains(&"adminer"));
        assert!(hints.contains(&"pgadmin"));
        assert!(hints.contains(&"phpmyadmin"));
        assert!(hints.contains(&"portainer"));
        assert!(hints.contains(&"traefik"));
    }
}
