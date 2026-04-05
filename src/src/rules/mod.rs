mod exposure;
mod permissions;
mod sensitive;
mod updates;

pub use exposure::{is_public_port, scan_exposure_risk};
pub use permissions::{classify_sensitive_mount, scan_permission_risk};
pub use sensitive::scan_sensitive_data;
pub use updates::{scan_update_risk, split_image_reference};

use crate::compose::ComposeProject;
use crate::domain::Finding;

#[derive(Debug, Default)]
pub struct RuleEngine;

impl RuleEngine {
    pub fn scan(&self, project: &ComposeProject) -> Vec<Finding> {
        let mut findings = Vec::new();
        findings.extend(scan_exposure_risk(project));
        findings.extend(scan_permission_risk(project));
        findings.extend(scan_sensitive_data(project));
        findings.extend(scan_update_risk(project));
        findings
    }
}

struct ServiceFindingText {
    title: String,
    description: String,
    why_risky: String,
    how_to_fix: String,
}

fn service_finding(
    id: &str,
    axis: crate::domain::Axis,
    severity: crate::domain::Severity,
    service_name: &str,
    text: ServiceFindingText,
    evidence: std::collections::BTreeMap<String, String>,
) -> Finding {
    Finding {
        id: id.to_owned(),
        axis,
        severity,
        scope: crate::domain::Scope::Service,
        source: crate::domain::Source::NativeCompose,
        subject: service_name.to_owned(),
        related_service: Some(service_name.to_owned()),
        title: text.title,
        description: text.description,
        why_risky: text.why_risky,
        how_to_fix: text.how_to_fix,
        evidence,
        remediation: crate::domain::RemediationKind::None,
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use crate::compose::ComposeParser;
    use crate::domain::Severity;

    use super::RuleEngine;

    fn fixture(service: &str, path: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/services")
            .join(service)
            .join(path)
            .canonicalize()
            .expect("fixture should exist")
    }

    #[test]
    fn gitea_baseline_stays_clear_under_generic_rules() {
        let project = ComposeParser::parse_path_without_override(fixture("gitea", "baseline.yml"))
            .expect("project should parse");

        let findings = RuleEngine.scan(&project);

        assert!(findings.is_empty());
    }

    #[test]
    fn gitea_vulnerable_fixture_produces_expected_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("gitea", "vulnerable.yml"))
                .expect("project should parse");

        let findings = RuleEngine.scan(&project);

        assert_eq!(
            findings
                .iter()
                .map(|finding| (
                    finding.id.as_str(),
                    finding.related_service.as_deref().unwrap_or_default(),
                    finding.severity,
                ))
                .collect::<Vec<_>>(),
            vec![
                ("exposure.public_binding", "server", Severity::Medium),
                ("exposure.reverse_proxy_expected", "server", Severity::High),
                ("permissions.implicit_root", "server", Severity::Medium),
                ("permissions.implicit_root", "db", Severity::Medium),
                ("sensitive.default_credential", "server", Severity::Critical),
                ("sensitive.inline_secret", "server", Severity::High),
                ("sensitive.inline_secret", "server", Severity::High),
                ("sensitive.default_credential", "db", Severity::Critical),
                ("updates.latest_tag", "server", Severity::High),
                ("updates.major_only_tag", "db", Severity::Low),
            ]
        );
    }
}
