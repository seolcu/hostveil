mod exposure;
mod permissions;
mod sensitive;
mod service_aware;
mod updates;

pub use exposure::{is_public_port, scan_exposure_risk};
pub use permissions::{classify_sensitive_mount, scan_permission_risk};
pub use sensitive::scan_sensitive_data;
pub use service_aware::scan_service_aware_risk;
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
        findings.extend(scan_service_aware_risk(project));
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
    fn vaultwarden_baseline_stays_clear_under_generic_rules() {
        let project =
            ComposeParser::parse_path_without_override(fixture("vaultwarden", "baseline.yml"))
                .expect("project should parse");

        let findings = RuleEngine.scan(&project);

        assert!(findings.is_empty());
    }

    #[test]
    fn vaultwarden_vulnerable_fixture_produces_expected_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("vaultwarden", "vulnerable.yml"))
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
                ("exposure.public_binding", "vaultwarden", Severity::Medium),
                (
                    "exposure.reverse_proxy_expected",
                    "vaultwarden",
                    Severity::High,
                ),
                ("permissions.implicit_root", "vaultwarden", Severity::Medium),
                ("sensitive.inline_secret", "vaultwarden", Severity::High),
                ("updates.latest_tag", "vaultwarden", Severity::High),
                (
                    "service.vaultwarden.signups_enabled",
                    "vaultwarden",
                    Severity::Medium,
                ),
                (
                    "service.vaultwarden.admin_surface_public",
                    "vaultwarden",
                    Severity::High,
                ),
                (
                    "service.vaultwarden.insecure_domain",
                    "vaultwarden",
                    Severity::High,
                ),
            ]
        );
    }

    #[test]
    fn jellyfin_baseline_stays_clear_under_generic_rules() {
        let project =
            ComposeParser::parse_path_without_override(fixture("jellyfin", "baseline.yml"))
                .expect("project should parse");

        let findings = RuleEngine.scan(&project);

        assert!(findings.is_empty());
    }

    #[test]
    fn jellyfin_vulnerable_fixture_produces_expected_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("jellyfin", "vulnerable.yml"))
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
                ("exposure.public_binding", "jellyfin", Severity::Medium),
                ("permissions.implicit_root", "jellyfin", Severity::Medium),
                ("updates.no_tag", "jellyfin", Severity::Medium),
                (
                    "service.jellyfin.insecure_published_url",
                    "jellyfin",
                    Severity::High,
                ),
                (
                    "service.jellyfin.discovery_public",
                    "jellyfin",
                    Severity::Medium,
                ),
                (
                    "service.jellyfin.media_mount_writable",
                    "jellyfin",
                    Severity::Low,
                ),
            ]
        );
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
                ("service.gitea.web_and_ssh_public", "server", Severity::High,),
                (
                    "service.gitea.ssh_published_public",
                    "server",
                    Severity::Medium,
                ),
                (
                    "service.gitea.inline_security_secrets",
                    "server",
                    Severity::High,
                ),
            ]
        );
    }

    #[test]
    fn immich_baseline_stays_clear_under_generic_rules() {
        let project = ComposeParser::parse_path_without_override(fixture("immich", "baseline.yml"))
            .expect("project should parse");

        let findings = RuleEngine.scan(&project);

        assert!(findings.is_empty());
    }

    #[test]
    fn immich_vulnerable_fixture_produces_expected_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("immich", "vulnerable.yml"))
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
                ("exposure.public_binding", "immich-server", Severity::Medium),
                (
                    "exposure.reverse_proxy_expected",
                    "immich-server",
                    Severity::High,
                ),
                (
                    "permissions.implicit_root",
                    "immich-server",
                    Severity::Medium
                ),
                (
                    "permissions.implicit_root",
                    "immich-machine-learning",
                    Severity::Medium,
                ),
                ("permissions.implicit_root", "redis", Severity::Medium),
                ("permissions.implicit_root", "database", Severity::Medium),
                (
                    "sensitive.env_file_plaintext",
                    "immich-server",
                    Severity::High
                ),
                (
                    "sensitive.env_file_plaintext",
                    "immich-machine-learning",
                    Severity::High,
                ),
                ("updates.major_only_tag", "immich-server", Severity::Low),
                (
                    "updates.major_only_tag",
                    "immich-machine-learning",
                    Severity::Low,
                ),
                ("updates.no_tag", "redis", Severity::Medium),
                ("updates.no_tag", "database", Severity::Medium),
                (
                    "service.immich.shared_secret_env_file",
                    "immich-server",
                    Severity::High,
                ),
                (
                    "service.immich.default_db_password",
                    "immich-server",
                    Severity::Critical,
                ),
            ]
        );
    }
}
