use serde::Serialize;
use serde_json::to_string_pretty;

use crate::domain::{Finding, ScanResult, ScoreReport};
use crate::i18n;

const JSON_SCHEMA_VERSION: &str = "0.13.0";
const SARIF_SCHEMA_URI: &str = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";
const SARIF_VERSION: &str = "2.1.0";
const TOOL_NAME: &str = "hostveil";
const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Versioned JSON export wrapper.
///
/// This struct stabilizes the top-level schema so downstream consumers
/// can rely on field presence even as internal `ScanResult` layout evolves.
#[derive(Debug, Clone, Serialize)]
struct JsonExport<'a> {
    version: &'a str,
    findings: &'a [Finding],
    #[serde(skip_serializing_if = "Option::is_none")]
    score_report: Option<&'a ScoreReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<&'a crate::domain::ScanMetadata>,
}

pub fn scan_result_json(scan_result: &ScanResult) -> String {
    scan_result_json_filtered(scan_result, false)
}

/// Export scan result as JSON, optionally omitting metadata and scores.
///
/// When `findings_only` is true, only the `findings` array is included,
/// producing a compact output suitable for piping into other tools.
pub fn scan_result_json_filtered(scan_result: &ScanResult, findings_only: bool) -> String {
    let export = if findings_only {
        JsonExport {
            version: JSON_SCHEMA_VERSION,
            findings: &scan_result.findings,
            score_report: None,
            metadata: None,
        }
    } else {
        JsonExport {
            version: JSON_SCHEMA_VERSION,
            findings: &scan_result.findings,
            score_report: Some(&scan_result.score_report),
            metadata: Some(&scan_result.metadata),
        }
    };

    to_string_pretty(&export).unwrap_or_else(|_| {
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

pub fn scan_result_sarif(scan_result: &ScanResult) -> String {
    let mut results = Vec::new();

    for finding in &scan_result.findings {
        let level = match finding.severity {
            crate::domain::Severity::Critical => "error",
            crate::domain::Severity::High => "error",
            crate::domain::Severity::Medium => "warning",
            crate::domain::Severity::Low => "note",
        };

        let location_uri = if finding.subject.is_empty() {
            String::from("unknown")
        } else {
            finding.subject.clone()
        };

        results.push(serde_json::json!({
            "ruleId": finding.id,
            "level": level,
            "message": {
                "text": finding.description
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": location_uri
                    }
                }
            }],
            "properties": {
                "title": finding.title,
                "severity": finding.severity.as_key(),
                "axis": finding.axis.as_key(),
                "scope": serde_json::to_value(finding.scope).unwrap_or_default(),
                "source": serde_json::to_value(finding.source).unwrap_or_default(),
                "remediation": serde_json::to_value(finding.remediation).unwrap_or_default(),
                "whyRisky": finding.why_risky,
                "howToFix": finding.how_to_fix,
                "relatedService": finding.related_service,
            }
        }));
    }

    let report = serde_json::json!({
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": TOOL_VERSION,
                    "informationUri": "https://github.com/seolcu/hostveil"
                }
            },
            "results": results,
            "properties": {
                "scoreReport": {
                    "overall": scan_result.score_report.overall,
                    "scanFocus": scan_result.score_report.scan_focus.iter().map(|a| a.as_key()).collect::<Vec<_>>(),
                }
            }
        }]
    });

    to_string_pretty(&report).unwrap_or_else(|_| {
        format!(
            "{{\n  \"$schema\": \"{}\",\n  \"version\": \"2.1.0\",\n  \"runs\": []\n}}\n",
            SARIF_SCHEMA_URI
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

    use super::{scan_result_json, scan_result_json_filtered};
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
        assert!(json["score_report"]["axis_scores"].is_object());
        assert!(json["score_report"]["severity_counts"]["critical"].is_number());
    }

    #[test]
    fn emits_versioned_schema() {
        let result = ScanResult::default();
        let json = parse_json(&result);

        assert_eq!(json["version"].as_str().unwrap(), "0.13.0");
        assert!(json["findings"].is_array());
        assert!(json["score_report"].is_object());
        assert!(json["metadata"].is_object());
    }

    #[test]
    fn findings_only_omits_score_and_metadata() {
        let mut result = ScanResult::default();
        result.findings.push(test_finding(
            "service.public_binding",
            Scope::Service,
            Source::NativeCompose,
            "web",
            Some("web"),
        ));

        let json: Value =
            serde_json::from_str(&scan_result_json_filtered(&result, true)).expect("should parse");

        assert_eq!(json["version"].as_str().unwrap(), "0.13.0");
        assert_eq!(json["findings"].as_array().unwrap().len(), 1);
        assert!(!json.as_object().unwrap().contains_key("score_report"));
        assert!(!json.as_object().unwrap().contains_key("metadata"));
    }

    use super::scan_result_sarif;

    #[test]
    fn sarif_emits_valid_schema_and_version() {
        let mut result = ScanResult::default();
        result.findings.push(test_finding(
            "test.finding",
            Scope::Service,
            Source::NativeCompose,
            "web",
            Some("web"),
        ));

        let sarif: Value =
            serde_json::from_str(&scan_result_sarif(&result)).expect("SARIF should parse");

        assert_eq!(sarif["version"], "2.1.0");
        assert!(
            sarif["$schema"]
                .as_str()
                .unwrap()
                .contains("sarif-schema-2.1.0.json")
        );
        assert!(sarif["runs"].is_array());
        assert_eq!(sarif["runs"].as_array().unwrap().len(), 1);

        let run = &sarif["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "hostveil");
        assert!(run["results"].is_array());
        assert_eq!(run["results"].as_array().unwrap().len(), 1);

        let result_item = &run["results"][0];
        assert_eq!(result_item["ruleId"], "test.finding");
        assert_eq!(result_item["level"], "error");
        assert_eq!(
            result_item["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "web"
        );
    }

    #[test]
    fn sarif_maps_severity_to_level_correctly() {
        let severities = [
            (crate::domain::Severity::Critical, "error"),
            (crate::domain::Severity::High, "error"),
            (crate::domain::Severity::Medium, "warning"),
            (crate::domain::Severity::Low, "note"),
        ];

        for (severity, expected_level) in severities {
            let mut result = ScanResult::default();
            let mut finding = test_finding(
                "test",
                Scope::Service,
                Source::NativeCompose,
                "svc",
                Some("svc"),
            );
            finding.severity = severity;
            result.findings.push(finding);

            let sarif: Value =
                serde_json::from_str(&scan_result_sarif(&result)).expect("SARIF should parse");
            assert_eq!(
                sarif["runs"][0]["results"][0]["level"], expected_level,
                "severity {severity:?} should map to level {expected_level}"
            );
        }
    }

    #[test]
    fn sarif_includes_score_report_in_properties() {
        let mut result = ScanResult::default();
        result.findings.push(test_finding(
            "test.finding",
            Scope::Service,
            Source::NativeCompose,
            "web",
            Some("web"),
        ));
        result.score_report.overall = 85;

        let sarif: Value =
            serde_json::from_str(&scan_result_sarif(&result)).expect("SARIF should parse");

        let props = &sarif["runs"][0]["properties"]["scoreReport"];
        assert_eq!(props["overall"], 85);
        assert!(props["scanFocus"].is_array());
    }

    #[test]
    fn sarif_empty_findings_produces_empty_results() {
        let result = ScanResult::default();
        let sarif: Value =
            serde_json::from_str(&scan_result_sarif(&result)).expect("SARIF should parse");

        let results = &sarif["runs"][0]["results"];
        assert!(results.is_array());
        assert_eq!(results.as_array().unwrap().len(), 0);
    }

    #[test]
    fn sarif_empty_subject_uses_unknown_uri() {
        let mut result = ScanResult::default();
        let mut finding = test_finding("test.finding", Scope::Host, Source::NativeHost, "", None);
        finding.subject = String::new();
        result.findings.push(finding);

        let sarif: Value =
            serde_json::from_str(&scan_result_sarif(&result)).expect("SARIF should parse");

        assert_eq!(
            sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uri"],
            "unknown"
        );
    }
}
