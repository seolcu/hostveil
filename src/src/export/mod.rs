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

    use super::scan_result_json;
    use crate::domain::{Axis, Finding, RemediationKind, ScanResult, Scope, Severity, Source};

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

    #[test]
    fn emits_valid_scan_result_shape() {
        let json = scan_result_json(&ScanResult::default());

        assert!(json.contains("\"findings\": []"));
        assert!(json.contains("\"score_report\":"));
        assert!(json.contains("\"metadata\":"));
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
}
