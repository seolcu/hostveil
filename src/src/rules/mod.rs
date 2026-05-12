mod exposure;
mod network;
mod permissions;
mod runtime;
mod sensitive;
mod service_aware;
mod updates;

pub use exposure::{is_public_port, scan_exposure_risk};
pub use network::scan_network_isolation;
pub use permissions::{classify_sensitive_mount, scan_permission_risk};
pub use runtime::scan_runtime_risk;
pub use sensitive::scan_sensitive_data;
pub use service_aware::scan_service_aware_risk;
pub use updates::{scan_update_risk, split_image_reference};

use crate::compose::ComposeProject;
use crate::domain::{Finding, RemediationKind};

#[derive(Debug, Default)]
pub struct RuleEngine;

impl RuleEngine {
    pub fn scan(&self, project: &ComposeProject) -> Vec<Finding> {
        let mut findings = Vec::new();
        findings.extend(scan_exposure_risk(project));
        findings.extend(scan_permission_risk(project));
        findings.extend(scan_runtime_risk(project));
        findings.extend(scan_sensitive_data(project));
        findings.extend(scan_update_risk(project));
        findings.extend(scan_service_aware_risk(project));
        findings.extend(scan_network_isolation(project));
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
    service_finding_with_remediation(
        id,
        axis,
        severity,
        service_name,
        text,
        evidence,
        RemediationKind::Manual,
    )
}

fn service_finding_with_remediation(
    id: &str,
    axis: crate::domain::Axis,
    severity: crate::domain::Severity,
    service_name: &str,
    text: ServiceFindingText,
    evidence: std::collections::BTreeMap<String, String>,
    remediation: RemediationKind,
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
        remediation,
    }
}

#[cfg(test)]
mod realistic_fixture_tests {
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
                (
                    "runtime.no_new_privileges_disabled",
                    "vaultwarden",
                    Severity::Low
                ),
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
                ("network.default_bridge_used", "", Severity::Low),
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
                (
                    "runtime.no_new_privileges_disabled",
                    "jellyfin",
                    Severity::Low
                ),
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
                ("network.default_bridge_used", "", Severity::Low),
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
                (
                    "runtime.no_new_privileges_disabled",
                    "server",
                    Severity::Low
                ),
                ("runtime.no_new_privileges_disabled", "db", Severity::Low),
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
                ("network.default_bridge_used", "", Severity::Low),
            ]
        );
    }

    #[test]
    fn immich_baseline_stays_clear_under_generic_rules() {
        let project = ComposeParser::parse_path_without_override(fixture("immich", "baseline.yml"))
            .expect("project should parse");

        let findings = RuleEngine.scan(&project);

        assert!(
            !findings
                .iter()
                .any(|f| f.id.starts_with("service.immich.") || f.id.starts_with("service.redis."))
        );
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
                    "runtime.no_new_privileges_disabled",
                    "immich-server",
                    Severity::Low
                ),
                (
                    "runtime.no_new_privileges_disabled",
                    "immich-machine-learning",
                    Severity::Low
                ),
                ("runtime.no_new_privileges_disabled", "redis", Severity::Low),
                (
                    "runtime.no_new_privileges_disabled",
                    "database",
                    Severity::Low
                ),
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
                ("service.redis.password_missing", "redis", Severity::High,),
                ("network.default_bridge_used", "", Severity::Low),
            ]
        );
    }

    #[test]
    fn nextcloud_baseline_stays_clear_under_generic_rules() {
        let project =
            ComposeParser::parse_path_without_override(fixture("nextcloud", "baseline.yml"))
                .expect("project should parse");

        let findings = RuleEngine.scan(&project);

        assert!(findings.is_empty());
    }

    #[test]
    fn nextcloud_vulnerable_fixture_produces_expected_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("nextcloud", "vulnerable.yml"))
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
                ("exposure.public_binding", "nextcloud", Severity::Medium),
                ("permissions.implicit_root", "nextcloud", Severity::Medium),
                (
                    "runtime.no_new_privileges_disabled",
                    "nextcloud",
                    Severity::Low
                ),
                (
                    "sensitive.default_credential",
                    "nextcloud",
                    Severity::Critical,
                ),
                ("updates.latest_tag", "nextcloud", Severity::High),
                (
                    "service.nextcloud.insecure_overwriteprotocol",
                    "nextcloud",
                    Severity::High,
                ),
                (
                    "service.nextcloud.wildcard_trusted_domains",
                    "nextcloud",
                    Severity::High,
                ),
                (
                    "service.nextcloud.default_admin_credentials",
                    "nextcloud",
                    Severity::Critical,
                ),
                ("network.default_bridge_used", "", Severity::Low),
            ]
        );
    }

    #[test]
    fn traefik_baseline_stays_clear_under_generic_rules() {
        let project =
            ComposeParser::parse_path_without_override(fixture("traefik", "baseline.yml"))
                .expect("project should parse");

        let findings = RuleEngine.scan(&project);

        assert!(findings.is_empty());
    }

    #[test]
    fn traefik_vulnerable_fixture_produces_expected_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("traefik", "vulnerable.yml"))
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
                ("exposure.public_binding", "traefik", Severity::Medium),
                (
                    "exposure.admin_interface_public",
                    "traefik",
                    Severity::Critical,
                ),
                ("permissions.implicit_root", "traefik", Severity::Medium),
                (
                    "runtime.no_new_privileges_disabled",
                    "traefik",
                    Severity::Low
                ),
                (
                    "service.traefik.insecure_api_enabled",
                    "traefik",
                    Severity::High,
                ),
                (
                    "service.traefik.dashboard_public",
                    "traefik",
                    Severity::Medium,
                ),
                ("network.default_bridge_used", "", Severity::Low),
            ]
        );
    }

    #[test]
    fn portainer_baseline_stays_clear_under_generic_rules() {
        let project =
            ComposeParser::parse_path_without_override(fixture("portainer", "baseline.yml"))
                .expect("project should parse");

        let findings = RuleEngine.scan(&project);

        assert!(findings.is_empty());
    }

    #[test]
    fn portainer_vulnerable_fixture_produces_expected_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("portainer", "vulnerable.yml"))
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
                ("exposure.public_binding", "portainer", Severity::Medium),
                (
                    "exposure.admin_interface_public",
                    "portainer",
                    Severity::Critical,
                ),
                ("permissions.implicit_root", "portainer", Severity::Medium),
                (
                    "permissions.sensitive_mount",
                    "portainer",
                    Severity::Critical,
                ),
                (
                    "runtime.no_new_privileges_disabled",
                    "portainer",
                    Severity::Low
                ),
                (
                    "service.portainer.admin_ui_public",
                    "portainer",
                    Severity::High,
                ),
                (
                    "service.portainer.docker_socket_mounted",
                    "portainer",
                    Severity::High,
                ),
                (
                    "service.portainer.auth_disabled",
                    "portainer",
                    Severity::Critical,
                ),
                ("network.default_bridge_used", "", Severity::Low),
            ]
        );
    }

    #[test]
    fn homeassistant_baseline_stays_clear_under_generic_rules() {
        let project =
            ComposeParser::parse_path_without_override(fixture("homeassistant", "baseline.yml"))
                .expect("project should parse");

        let findings = RuleEngine.scan(&project);

        assert!(findings.is_empty());
    }

    #[test]
    fn homeassistant_vulnerable_fixture_produces_expected_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("homeassistant", "vulnerable.yml"))
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
                ("exposure.public_binding", "homeassistant", Severity::Medium),
                (
                    "permissions.implicit_root",
                    "homeassistant",
                    Severity::Medium
                ),
                ("permissions.host_network", "homeassistant", Severity::High,),
                (
                    "runtime.no_new_privileges_disabled",
                    "homeassistant",
                    Severity::Low
                ),
                (
                    "service.homeassistant.ui_public",
                    "homeassistant",
                    Severity::Medium,
                ),
                (
                    "service.homeassistant.host_network",
                    "homeassistant",
                    Severity::Medium,
                ),
                (
                    "service.homeassistant.device_mount",
                    "homeassistant",
                    Severity::Low,
                ),
                ("network.host_mode", "homeassistant", Severity::High,),
                ("network.default_bridge_used", "", Severity::Low),
            ]
        );
    }

    #[test]
    fn pihole_baseline_stays_clear_under_generic_rules() {
        let project = ComposeParser::parse_path_without_override(fixture("pihole", "baseline.yml"))
            .expect("project should parse");

        let findings = RuleEngine.scan(&project);
        if !findings.is_empty() {
            eprintln!(
                "Pi-hole baseline findings: {:?}",
                findings
                    .iter()
                    .map(|f| (&f.id, &f.related_service, &f.severity))
                    .collect::<Vec<_>>()
            );
        }

        assert!(findings.is_empty());
    }

    #[test]
    fn pihole_vulnerable_fixture_produces_expected_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("pihole", "vulnerable.yml"))
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
                ("exposure.public_binding", "pihole", Severity::Medium),
                ("permissions.implicit_root", "pihole", Severity::Medium),
                (
                    "runtime.no_new_privileges_disabled",
                    "pihole",
                    Severity::Low
                ),
                ("sensitive.default_credential", "pihole", Severity::Critical,),
                ("service.pihole.admin_public", "pihole", Severity::High,),
                ("service.pihole.weak_password", "pihole", Severity::High,),
                ("service.pihole.dns_public", "pihole", Severity::Medium,),
                ("network.default_bridge_used", "", Severity::Low),
            ]
        );
    }

    #[test]
    fn grafana_baseline_stays_clear_under_generic_rules() {
        let project =
            ComposeParser::parse_path_without_override(fixture("grafana", "baseline.yml"))
                .expect("project should parse");

        let findings = RuleEngine.scan(&project);

        assert!(findings.is_empty());
    }

    #[test]
    fn grafana_vulnerable_fixture_produces_expected_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("grafana", "vulnerable.yml"))
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
                ("exposure.public_binding", "grafana", Severity::Medium),
                ("permissions.implicit_root", "grafana", Severity::Medium),
                (
                    "runtime.no_new_privileges_disabled",
                    "grafana",
                    Severity::Low
                ),
                (
                    "sensitive.default_credential",
                    "grafana",
                    Severity::Critical,
                ),
                ("service.grafana.admin_public", "grafana", Severity::High,),
                (
                    "service.grafana.auth_disabled",
                    "grafana",
                    Severity::Critical,
                ),
                (
                    "service.grafana.anonymous_access",
                    "grafana",
                    Severity::High,
                ),
                ("network.default_bridge_used", "", Severity::Low),
            ]
        );
    }

    #[test]
    fn npm_baseline_stays_clear_under_generic_rules() {
        let project = ComposeParser::parse_path_without_override(fixture("npm", "baseline.yml"))
            .expect("project should parse");

        let findings = RuleEngine.scan(&project);

        assert!(findings.is_empty());
    }

    #[test]
    fn npm_vulnerable_fixture_produces_expected_findings() {
        let project = ComposeParser::parse_path_without_override(fixture("npm", "vulnerable.yml"))
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
                ("exposure.public_binding", "npm", Severity::Medium),
                ("permissions.implicit_root", "npm", Severity::Medium),
                ("runtime.no_new_privileges_disabled", "npm", Severity::Low),
                ("service.npm.admin_public", "npm", Severity::High,),
                ("network.default_bridge_used", "", Severity::Low),
            ]
        );
    }

    #[test]
    fn authentik_baseline_stays_clear_under_generic_rules() {
        let project =
            ComposeParser::parse_path_without_override(fixture("authentik", "baseline.yml"))
                .expect("project should parse");

        let findings = RuleEngine.scan(&project);

        assert!(findings.is_empty());
    }

    #[test]
    fn authentik_vulnerable_fixture_produces_expected_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("authentik", "vulnerable.yml"))
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
                ("exposure.public_binding", "authentik", Severity::Medium),
                ("permissions.implicit_root", "authentik", Severity::Medium),
                (
                    "runtime.no_new_privileges_disabled",
                    "authentik",
                    Severity::Low
                ),
                (
                    "service.authentik.admin_public",
                    "authentik",
                    Severity::High,
                ),
                (
                    "service.authentik.debug_enabled",
                    "authentik",
                    Severity::Medium,
                ),
                ("network.default_bridge_used", "", Severity::Low),
            ]
        );
    }

    #[test]
    fn paperless_baseline_stays_clear_under_generic_rules() {
        let project =
            ComposeParser::parse_path_without_override(fixture("paperless", "baseline.yml"))
                .expect("project should parse");

        let findings = RuleEngine.scan(&project);

        assert!(findings.is_empty());
    }

    #[test]
    fn paperless_vulnerable_fixture_produces_expected_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("paperless", "vulnerable.yml"))
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
                ("exposure.public_binding", "paperless", Severity::Medium),
                ("permissions.implicit_root", "paperless", Severity::Medium),
                (
                    "runtime.no_new_privileges_disabled",
                    "paperless",
                    Severity::Low
                ),
                ("service.paperless.ui_public", "paperless", Severity::Medium,),
                (
                    "service.paperless.no_force_login",
                    "paperless",
                    Severity::Medium,
                ),
                ("network.default_bridge_used", "", Severity::Low),
            ]
        );
    }

    #[test]
    fn postgres_baseline_stays_clear_under_generic_rules() {
        let project =
            ComposeParser::parse_path_without_override(fixture("postgres", "baseline.yml"))
                .expect("project should parse");

        let findings = RuleEngine.scan(&project);

        assert!(
            !findings
                .iter()
                .any(|f| f.source == crate::domain::Source::NativeCompose
                    && f.id.starts_with("service.postgres."))
        );
    }

    #[test]
    fn postgres_vulnerable_fixture_produces_expected_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("postgres", "vulnerable.yml"))
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
                ("exposure.public_binding", "db", Severity::Medium),
                ("permissions.implicit_root", "db", Severity::Medium),
                ("runtime.no_new_privileges_disabled", "db", Severity::Low),
                (
                    "service.postgres.password_missing",
                    "db",
                    Severity::Critical
                ),
                ("service.postgres.bind_public", "db", Severity::High),
                ("service.postgres.trust_auth", "db", Severity::High),
                ("network.default_bridge_used", "", Severity::Low),
            ]
        );
    }

    #[test]
    fn mysql_baseline_stays_clear_under_generic_rules() {
        let project = ComposeParser::parse_path_without_override(fixture("mysql", "baseline.yml"))
            .expect("project should parse");

        let findings = RuleEngine.scan(&project);

        assert!(
            !findings
                .iter()
                .any(|f| f.source == crate::domain::Source::NativeCompose
                    && f.id.starts_with("service.mysql."))
        );
    }

    #[test]
    fn mysql_vulnerable_fixture_produces_expected_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("mysql", "vulnerable.yml"))
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
                ("exposure.public_binding", "db", Severity::Medium),
                ("permissions.implicit_root", "db", Severity::Medium),
                ("runtime.no_new_privileges_disabled", "db", Severity::Low),
                ("service.mysql.password_missing", "db", Severity::Critical),
                ("service.mysql.bind_public", "db", Severity::High),
                ("network.default_bridge_used", "", Severity::Low),
            ]
        );
    }

    #[test]
    fn redis_baseline_stays_clear_under_generic_rules() {
        let project = ComposeParser::parse_path_without_override(fixture("redis", "baseline.yml"))
            .expect("project should parse");

        let findings = RuleEngine.scan(&project);

        assert!(findings.is_empty());
    }

    #[test]
    fn redis_vulnerable_fixture_produces_expected_findings() {
        let project =
            ComposeParser::parse_path_without_override(fixture("redis", "vulnerable.yml"))
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
                ("exposure.public_binding", "cache", Severity::Medium),
                ("permissions.implicit_root", "cache", Severity::Medium),
                ("runtime.no_new_privileges_disabled", "cache", Severity::Low),
                ("service.redis.password_missing", "cache", Severity::High),
                ("service.redis.bind_public", "cache", Severity::High),
                (
                    "service.redis.protected_mode_disabled",
                    "cache",
                    Severity::High
                ),
                ("network.default_bridge_used", "", Severity::Low),
            ]
        );
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use crate::compose::ComposeParser;
    use crate::domain::Severity;

    use super::RuleEngine;

    fn fixture(path: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/rules")
            .join(path)
            .canonicalize()
            .expect("fixture should exist")
    }

    #[test]
    fn hardened_stack_stays_free_of_false_positives() {
        let project = ComposeParser::parse_path_without_override(fixture("hardened-stack.yml"))
            .expect("project should parse");

        let findings = RuleEngine.scan(&project);

        assert!(findings.is_empty());
    }

    #[test]
    fn mixed_stack_produces_expected_findings_and_severities() {
        let project =
            ComposeParser::parse_path(fixture("mixed-stack")).expect("project should parse");

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
                ("exposure.public_binding", "vaultwarden", Severity::Medium,),
                (
                    "exposure.reverse_proxy_expected",
                    "vaultwarden",
                    Severity::High,
                ),
                ("exposure.public_binding", "adminer", Severity::Medium),
                (
                    "exposure.admin_interface_public",
                    "adminer",
                    Severity::Critical,
                ),
                ("permissions.root_user", "adminer", Severity::High),
                ("permissions.implicit_root", "postgres", Severity::Medium,),
                ("permissions.privileged", "backup", Severity::Critical),
                (
                    "runtime.no_new_privileges_disabled",
                    "vaultwarden",
                    Severity::Low
                ),
                (
                    "runtime.no_new_privileges_disabled",
                    "adminer",
                    Severity::Low
                ),
                (
                    "runtime.no_new_privileges_disabled",
                    "postgres",
                    Severity::Low
                ),
                ("sensitive.inline_secret", "vaultwarden", Severity::High),
                ("sensitive.env_file_plaintext", "postgres", Severity::High,),
                ("updates.latest_tag", "vaultwarden", Severity::High),
                ("updates.latest_tag", "adminer", Severity::High),
                ("updates.no_tag", "postgres", Severity::Medium),
                (
                    "service.vaultwarden.admin_surface_public",
                    "vaultwarden",
                    Severity::High,
                ),
                (
                    "service.postgres.password_missing",
                    "postgres",
                    Severity::Critical,
                ),
                ("network.default_bridge_used", "", Severity::Low),
            ]
        );
    }
}
