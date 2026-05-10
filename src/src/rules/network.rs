use std::collections::BTreeMap;

use crate::compose::ComposeProject;
use crate::domain::{Axis, Finding, RemediationKind, Scope, Severity, Source};
use crate::rules::exposure::is_public_port;

pub fn scan_network_isolation(project: &ComposeProject) -> Vec<Finding> {
    let mut findings = Vec::new();
    let has_custom_networks = !project.networks.is_empty();

    for service in project.services.values() {
        if service.network_mode.as_deref() == Some("bridge") {
            let public_ports: Vec<_> = service.ports.iter().filter(|p| is_public_port(p)).collect();
            if !public_ports.is_empty() {
                let first = &public_ports[0];
                findings.push(Finding {
                    id: "network.bridge_mode_public_ports".to_owned(),
                    axis: Axis::UnnecessaryExposure,
                    severity: Severity::Medium,
                    scope: Scope::Service,
                    source: Source::NativeCompose,
                    subject: service.name.clone(),
                    related_service: Some(service.name.clone()),
                    title: t!("finding.network.bridge_mode_public_ports.title").into_owned(),
                    description: t!(
                        "finding.network.bridge_mode_public_ports.description",
                        service = service.name.as_str(),
                        port = first.raw.as_str()
                    )
                    .into_owned(),
                    why_risky: t!("finding.network.bridge_mode_public_ports.why").into_owned(),
                    how_to_fix: t!("finding.network.bridge_mode_public_ports.fix").into_owned(),
                    evidence: BTreeMap::from([
                        (String::from("port"), first.raw.clone()),
                        (
                            String::from("host_ip"),
                            first
                                .host_ip
                                .clone()
                                .unwrap_or_else(|| String::from("0.0.0.0")),
                        ),
                    ]),
                    remediation: RemediationKind::None,
                });
            }
        }

        // Host network mode shares the host's network stack
        if service.network_mode.as_deref() == Some("host") {
            findings.push(Finding {
                id: "network.host_mode".to_owned(),
                axis: Axis::UnnecessaryExposure,
                severity: Severity::High,
                scope: Scope::Service,
                source: Source::NativeCompose,
                subject: service.name.clone(),
                related_service: Some(service.name.clone()),
                title: t!("finding.network.host_mode.title").into_owned(),
                description: t!(
                    "finding.network.host_mode.description",
                    service = service.name.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.network.host_mode.why").into_owned(),
                how_to_fix: t!("finding.network.host_mode.fix").into_owned(),
                evidence: BTreeMap::new(),
                remediation: RemediationKind::None,
            });
        }
    }

    let has_exposed_service = project.services.values().any(|service| {
        service.network_mode.as_deref() == Some("bridge")
            || service.network_mode.as_deref() == Some("host")
            || service.ports.iter().any(is_public_port)
    });

    if !has_custom_networks && has_exposed_service {
        findings.push(Finding {
            id: "network.default_bridge_used".to_owned(),
            axis: Axis::UnnecessaryExposure,
            severity: Severity::Low,
            scope: Scope::Project,
            source: Source::NativeCompose,
            subject: project.primary_file.display().to_string(),
            related_service: None,
            title: t!("finding.network.default_bridge_used.title").into_owned(),
            description: t!("finding.network.default_bridge_used.description").into_owned(),
            why_risky: t!("finding.network.default_bridge_used.why").into_owned(),
            how_to_fix: t!("finding.network.default_bridge_used.fix").into_owned(),
            evidence: BTreeMap::new(),
            remediation: RemediationKind::None,
        });
    }

    findings
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use crate::compose::ComposeParser;
    use crate::domain::{Scope, Severity};

    use super::*;

    fn fixture(path: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/rules")
            .join(path)
            .canonicalize()
            .expect("fixture should exist")
    }

    #[test]
    fn baseline_with_custom_networks_stays_clear() {
        let project =
            ComposeParser::parse_path_without_override(fixture("network-isolation-baseline.yml"))
                .expect("project should parse");

        let findings = scan_network_isolation(&project);
        assert!(findings.is_empty());
    }

    #[test]
    fn vulnerable_stack_detects_default_bridge_and_bridge_mode_ports() {
        let project =
            ComposeParser::parse_path_without_override(fixture("network-isolation-vulnerable.yml"))
                .expect("project should parse");

        let findings = scan_network_isolation(&project);

        assert_eq!(findings.len(), 2); // bridge_public + host_mode (custom networks exist, no default_bridge)

        let bridge_public = findings
            .iter()
            .find(|f| f.id == "network.bridge_mode_public_ports")
            .expect("bridge mode public ports finding should exist");
        assert_eq!(bridge_public.severity, Severity::Medium);
        assert_eq!(bridge_public.scope, Scope::Service);
        assert_eq!(bridge_public.related_service.as_deref(), Some("db"));

        let host_mode = findings
            .iter()
            .find(|f| f.id == "network.host_mode")
            .expect("host mode finding should exist");
        assert_eq!(host_mode.severity, Severity::High);
        assert_eq!(host_mode.scope, Scope::Service);
        assert_eq!(host_mode.related_service.as_deref(), Some("privileged"));
    }

    #[test]
    fn host_mode_service_finding() {
        let project =
            ComposeParser::parse_path_without_override(fixture("network-host-mode.yml"))
                .expect("project should parse");
        let findings = scan_network_isolation(&project);
        // host_mode + default_bridge_used (because app has no custom networks)
        assert_eq!(findings.len(), 2);
        let host_mode = findings
            .iter()
            .find(|f| f.id == "network.host_mode")
            .expect("host mode finding should exist");
        assert_eq!(host_mode.severity, Severity::High);
    }
}
