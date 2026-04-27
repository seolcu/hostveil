use serde_json::to_string_pretty;

use crate::domain::ScanResult;
use crate::i18n;

pub fn scan_result_json(scan_result: &ScanResult) -> String {
    to_string_pretty(scan_result).unwrap_or_else(|_| {
        format!(
            concat!(
                "{{\n",
                "  \"status\": \"error\",\n",
                "  \"message\": \"{}\"\n",
                "}}\n"
            ),
            escape_json(&i18n::tr("app.error.json_export_failed"))
        )
    }) + "\n"
}

fn escape_json(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use serde_json::Value;

    use super::scan_result_json;
    use crate::domain::{
        AdapterStatus, Axis, DefensiveControlStatus, DiscoveredProjectSummary,
        DockerDiscoveryStatus, Finding, HostRuntimeInfo, RemediationKind, ScanMetadata, ScanMode,
        ScanResult, Scope, ServiceSummary, Severity, Source,
    };

    fn test_finding(
        id: &str,
        scope: Scope,
        source: Source,
        subject: &str,
        related_service: Option<&str>,
    ) -> Finding {
        Finding {
            id: id.to_owned(),
            axis: Axis::UpdateSupplyChainRisk,
            severity: Severity::High,
            scope,
            source,
            subject: subject.to_owned(),
            related_service: related_service.map(str::to_owned),
            title: format!("Synthetic finding {id}"),
            description: format!("Synthetic description for {id}"),
            why_risky: String::from("Synthetic risk explanation"),
            how_to_fix: String::from("Synthetic remediation guidance"),
            evidence: BTreeMap::from([(String::from("subject"), subject.to_owned())]),
            remediation: RemediationKind::None,
        }
    }

    fn parse_json(scan_result: &ScanResult) -> Value {
        serde_json::from_str(&scan_result_json(scan_result)).expect("exported JSON should parse")
    }

    #[test]
    fn emits_valid_scan_result_shape() {
        let json = parse_json(&ScanResult::default());
        let root = json
            .as_object()
            .expect("scan_result_json should return a JSON object");

        assert!(root.contains_key("findings"));
        assert!(root.contains_key("score_report"));
        assert!(root.contains_key("metadata"));
        assert!(json["findings"].is_array());
        assert!(json["score_report"]["overall"].is_number());
        assert!(json["score_report"]["axis_scores"].is_object());
        assert!(json["score_report"]["severity_counts"].is_object());
        assert!(json["score_report"]["axis_weights"].is_object());
        assert!(json["score_report"]["severity_deductions"].is_object());
        assert!(json["metadata"]["adapters"].is_object());
        assert!(json["metadata"]["warnings"].is_array());
    }

    #[test]
    fn serializes_mixed_scopes_and_sources() {
        let result = ScanResult {
            findings: vec![
                test_finding(
                    "service.public_binding",
                    Scope::Service,
                    Source::NativeCompose,
                    "web",
                    Some("web"),
                ),
                test_finding(
                    "trivy.image_vulnerabilities.nginx",
                    Scope::Image,
                    Source::Trivy,
                    "nginx:1.27.5",
                    Some("web"),
                ),
                test_finding(
                    "lynis.ssh.password_authentication_enabled",
                    Scope::Host,
                    Source::Lynis,
                    "/etc/ssh/sshd_config",
                    None,
                ),
                test_finding(
                    "project.compose_bundle_loaded",
                    Scope::Project,
                    Source::NativeCompose,
                    "/srv/demo/docker-compose.yml",
                    None,
                ),
            ],
            ..Default::default()
        };

        let json = scan_result_json(&result);

        assert!(json.contains("\"scope\": \"service\""));
        assert!(json.contains("\"scope\": \"image\""));
        assert!(json.contains("\"scope\": \"host\""));
        assert!(json.contains("\"scope\": \"project\""));
        assert!(json.contains("\"source\": \"native_compose\""));
        assert!(json.contains("\"source\": \"trivy\""));
        assert!(json.contains("\"source\": \"lynis\""));
    }

    #[test]
    fn preserves_key_metadata_and_adapter_contract_fields() {
        let mut adapters = BTreeMap::new();
        adapters.insert(String::from("trivy"), AdapterStatus::Available);
        adapters.insert(
            String::from("lynis"),
            AdapterStatus::Failed(String::from("command crashed")),
        );
        adapters.insert(
            String::from("dockle"),
            AdapterStatus::Skipped(String::from("no image targets")),
        );

        let result = ScanResult {
            findings: vec![test_finding(
                "service.public_binding",
                Scope::Service,
                Source::NativeCompose,
                "web",
                Some("web"),
            )],
            metadata: ScanMetadata {
                scan_mode: ScanMode::Live,
                compose_root: Some(PathBuf::from("/srv/demo")),
                compose_file: Some(PathBuf::from("/srv/demo/compose.yaml")),
                host_root: Some(PathBuf::from("/")),
                host_runtime: Some(HostRuntimeInfo {
                    hostname: Some(String::from("demo-host")),
                    docker_version: Some(String::from("28.0.1")),
                    uptime: Some(String::from("2d 1h 4m")),
                    load_average: Some(String::from("0.21 0.19 0.17")),
                    fail2ban: DefensiveControlStatus::Enabled,
                    fail2ban_jails: Some(3),
                    fail2ban_banned_ips: Some(0),
                }),
                loaded_files: vec![
                    PathBuf::from("/srv/demo/compose.yaml"),
                    PathBuf::from("/srv/demo/compose.override.yaml"),
                ],
                service_count: 1,
                services: vec![ServiceSummary {
                    name: String::from("web"),
                    image: Some(String::from("nginx:1.27.5")),
                }],
                discovered_projects: vec![DiscoveredProjectSummary {
                    name: String::from("demo"),
                    source: String::from("docker"),
                    compose_path: Some(PathBuf::from("/srv/demo/compose.yaml")),
                    working_dir: Some(PathBuf::from("/srv/demo")),
                    service_count: 1,
                }],
                docker_status: Some(DockerDiscoveryStatus::Failed(String::from(
                    "permission denied",
                ))),
                warnings: vec![String::from("discovery fallback was used")],
                adapters,
            },
            ..Default::default()
        };

        let json = parse_json(&result);

        assert_eq!(json["metadata"]["scan_mode"], "live");
        assert_eq!(json["metadata"]["compose_root"], "/srv/demo");
        assert_eq!(json["metadata"]["compose_file"], "/srv/demo/compose.yaml");
        assert_eq!(json["metadata"]["host_root"], "/");
        assert_eq!(json["metadata"]["service_count"], 1);
        assert_eq!(json["metadata"]["services"][0]["name"], "web");
        assert_eq!(json["metadata"]["services"][0]["image"], "nginx:1.27.5");
        assert_eq!(json["metadata"]["docker_status"]["state"], "failed");
        assert_eq!(
            json["metadata"]["docker_status"]["detail"],
            "permission denied"
        );
        assert_eq!(json["metadata"]["adapters"]["trivy"]["state"], "available");
        assert_eq!(json["metadata"]["adapters"]["lynis"]["state"], "failed");
        assert_eq!(
            json["metadata"]["adapters"]["lynis"]["detail"],
            "command crashed"
        );
        assert_eq!(json["metadata"]["adapters"]["dockle"]["state"], "skipped");
        assert_eq!(
            json["metadata"]["adapters"]["dockle"]["detail"],
            "no image targets"
        );
        assert_eq!(json["findings"][0]["id"], "service.public_binding");
        assert_eq!(json["findings"][0]["scope"], "service");
        assert_eq!(json["findings"][0]["source"], "native_compose");
        assert_eq!(json["findings"][0]["evidence"]["subject"], "web");
        assert!(json["score_report"]["axis_scores"]["sensitive_data"].is_number());
        assert!(json["score_report"]["severity_counts"]["critical"].is_number());
    }
}
