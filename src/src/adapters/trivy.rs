use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;
use std::time::Duration;

use serde::Deserialize;

use crate::adapters::command;
use crate::domain::{
    AdapterStatus, Axis, Finding, RemediationKind, Scope, ServiceSummary, Severity, Source,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrivyScanOutput {
    pub status: AdapterStatus,
    pub findings: Vec<Finding>,
    pub warnings: Vec<String>,
}

pub fn scan(services: &[ServiceSummary]) -> TrivyScanOutput {
    scan_with_commands(services, "trivy", "trivy", command::DEFAULT_ADAPTER_TIMEOUT)
}

fn scan_with_commands(
    services: &[ServiceSummary],
    detect_command: &str,
    scan_command: &str,
    timeout: Duration,
) -> TrivyScanOutput {
    let mut output = TrivyScanOutput {
        status: AdapterStatus::Missing,
        findings: Vec::new(),
        warnings: Vec::new(),
    };
    let mut successful_scans = 0_usize;
    let mut first_scan_error: Option<String> = None;

    let images = dedup_images(services);
    if images.is_empty() {
        output.status = AdapterStatus::Skipped(t!("adapter.reason.no_image_targets").into_owned());
        return output;
    }

    match detect_trivy_with_command_and_timeout(detect_command, timeout) {
        TrivyAvailability::Missing => {
            output.status = AdapterStatus::Missing;
            return output;
        }
        TrivyAvailability::Available => {
            output.status = AdapterStatus::Available;
        }
        TrivyAvailability::Failed(detail) => {
            output.status = AdapterStatus::Failed(detail);
            return output;
        }
    }

    for image in images {
        match scan_image_with_command(scan_command, &image, timeout) {
            Ok(Some(summary)) => {
                successful_scans += 1;
                output.findings.push(summary_to_finding(&summary, services));
            }
            Ok(None) => successful_scans += 1,
            Err(error) => {
                if first_scan_error.is_none() {
                    first_scan_error = Some(error.clone());
                }
                output
                    .warnings
                    .push(crate::i18n::tr_adapter_scan_failed("Trivy", &image, &error));
            }
        }
    }

    finalize_status_after_image_scans(&mut output, successful_scans, first_scan_error);

    output
}

fn finalize_status_after_image_scans(
    output: &mut TrivyScanOutput,
    successful_scans: usize,
    first_scan_error: Option<String>,
) {
    if successful_scans == 0
        && let Some(error) = first_scan_error
    {
        output.status = AdapterStatus::Failed(error);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TrivyAvailability {
    Available,
    Missing,
    Failed(String),
}

#[cfg(test)]
fn detect_trivy_with_command(command_name: &str) -> TrivyAvailability {
    detect_trivy_with_command_and_timeout(command_name, command::DEFAULT_ADAPTER_TIMEOUT)
}

fn detect_trivy_with_command_and_timeout(
    command_name: &str,
    timeout: Duration,
) -> TrivyAvailability {
    let mut command = Command::new(command_name);
    command.arg("--version").env("NO_COLOR", "1");
    let output = command::run_with_timeout(command, timeout);

    match output {
        Ok(output) if output.status.success() => TrivyAvailability::Available,
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            TrivyAvailability::Failed(truncate(stderr.trim(), 200))
        }
        Err(error) if error.is_not_found() => TrivyAvailability::Missing,
        Err(error) => TrivyAvailability::Failed(truncate(&error.detail(), 200)),
    }
}

fn dedup_images(services: &[ServiceSummary]) -> Vec<String> {
    let mut images = BTreeSet::new();
    for service in services {
        if let Some(image) = &service.image {
            let trimmed = image.trim();
            if !trimmed.is_empty() {
                images.insert(trimmed.to_owned());
            }
        }
    }

    images.into_iter().collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrivyImageSummary {
    image: String,
    target: Option<String>,
    counts: BTreeMap<Severity, usize>,
    max_severity: Severity,
    total: usize,
    sample_ids: Vec<String>,
}

fn scan_image_with_command(
    command_name: &str,
    image: &str,
    timeout: Duration,
) -> Result<Option<TrivyImageSummary>, String> {
    let cache_dir = temp_trivy_cache_dir();
    let cache_path = cache_dir.display().to_string();

    let result = run_trivy_command(command_name, image, &cache_path, timeout);

    // If the first attempt failed with a cache lock / timeout message, wait a
    // moment and retry once with a fresh cache directory.
    let output = match result {
        Ok(output) => output,
        Err(error) if is_cache_lock_error(&error) => {
            let _ = std::fs::remove_dir_all(&cache_dir);
            std::thread::sleep(Duration::from_millis(500));

            let cache_dir = temp_trivy_cache_dir();
            let cache_path = cache_dir.display().to_string();
            let retry_result = run_trivy_command(command_name, image, &cache_path, timeout);
            let output = retry_result.map_err(|error| error.detail())?;
            let _ = std::fs::remove_dir_all(&cache_dir);
            output
        }
        Err(error) => {
            let _ = std::fs::remove_dir_all(&cache_dir);
            return Err(error.detail());
        }
    };

    let _ = std::fs::remove_dir_all(&cache_dir);

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let detail = if !stderr.trim().is_empty() {
            stderr.trim().to_owned()
        } else {
            stdout.trim().to_owned()
        };

        return Err(truncate(&detail, 240));
    }

    let report: TrivyReport = serde_json::from_slice(&output.stdout)
        .map_err(|error| crate::i18n::tr_adapter_json_parse_failed("Trivy", &error.to_string()))?;

    Ok(summarize_report(image, report))
}

fn run_trivy_command(
    command_name: &str,
    image: &str,
    cache_path: &str,
    timeout: Duration,
) -> Result<command::CommandOutput, command::CommandError> {
    let mut command = Command::new(command_name);
    command
        .args(trivy_image_args(image))
        .arg("--cache-dir")
        .arg(cache_path)
        .env("NO_COLOR", "1");
    command::run_with_timeout(command, timeout)
}

fn temp_trivy_cache_dir() -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time should move forward")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "hostveil-trivy-cache-{}-{nanos}",
        std::process::id()
    ))
}

fn is_cache_lock_error(error: &command::CommandError) -> bool {
    let lower = error.detail().to_ascii_lowercase();
    lower.contains("cache") && (lower.contains("lock") || lower.contains("timeout"))
}

fn trivy_image_args(image: &str) -> [&str; 7] {
    [
        "image",
        "--quiet",
        "--format",
        "json",
        "--scanners",
        "vuln",
        image,
    ]
}

fn summarize_report(image: &str, report: TrivyReport) -> Option<TrivyImageSummary> {
    let mut counts: BTreeMap<Severity, usize> = Severity::ALL.into_iter().map(|s| (s, 0)).collect();
    let mut sample_ids: Vec<String> = Vec::new();
    let mut target: Option<String> = None;

    let mut max_severity: Option<Severity> = None;

    for result in report.results.unwrap_or_default() {
        if target.is_none() {
            target = result.target.clone();
        }

        for vuln in result.vulnerabilities.unwrap_or_default() {
            let Some(severity) = vuln.severity.as_deref().and_then(parse_trivy_severity) else {
                continue;
            };

            *counts.entry(severity).or_insert(0) += 1;

            if max_severity.is_none_or(|current| severity_rank(severity) < severity_rank(current)) {
                max_severity = Some(severity);
            }

            if sample_ids.len() < 5
                && let Some(id) = vuln.vulnerability_id
            {
                sample_ids.push(id);
            }
        }
    }

    let total: usize = counts.values().sum();
    let max_severity = max_severity?;

    Some(TrivyImageSummary {
        image: image.to_owned(),
        target,
        counts,
        max_severity,
        total,
        sample_ids,
    })
}

fn summary_to_finding(summary: &TrivyImageSummary, services: &[ServiceSummary]) -> Finding {
    let related_service = related_service_for_image(&summary.image, services);

    let mut evidence = BTreeMap::new();
    evidence.insert(String::from("image"), summary.image.clone());
    if let Some(target) = &summary.target {
        evidence.insert(String::from("target"), target.clone());
    }
    evidence.insert(
        String::from("vulnerabilities_total"),
        summary.total.to_string(),
    );
    evidence.insert(
        String::from("critical"),
        summary
            .counts
            .get(&Severity::Critical)
            .copied()
            .unwrap_or_default()
            .to_string(),
    );
    evidence.insert(
        String::from("high"),
        summary
            .counts
            .get(&Severity::High)
            .copied()
            .unwrap_or_default()
            .to_string(),
    );
    evidence.insert(
        String::from("medium"),
        summary
            .counts
            .get(&Severity::Medium)
            .copied()
            .unwrap_or_default()
            .to_string(),
    );
    evidence.insert(
        String::from("low"),
        summary
            .counts
            .get(&Severity::Low)
            .copied()
            .unwrap_or_default()
            .to_string(),
    );
    if !summary.sample_ids.is_empty() {
        evidence.insert(String::from("sample_ids"), summary.sample_ids.join(", "));
    }

    Finding {
        id: format!("trivy.image_vulnerabilities.{}", slug(&summary.image)),
        axis: Axis::UpdateSupplyChainRisk,
        severity: summary.max_severity,
        scope: Scope::Image,
        source: Source::Trivy,
        subject: summary.image.clone(),
        related_service,
        title: t!("finding.trivy.image_vulnerabilities.title").into_owned(),
        description: t!(
            "finding.trivy.image_vulnerabilities.description",
            image = summary.image,
            count = summary.total
        )
        .into_owned(),
        why_risky: t!("finding.trivy.image_vulnerabilities.why").into_owned(),
        how_to_fix: t!("finding.trivy.image_vulnerabilities.fix").into_owned(),
        evidence,
        remediation: RemediationKind::None,
    }
}

fn related_service_for_image(image: &str, services: &[ServiceSummary]) -> Option<String> {
    services
        .iter()
        .find(|service| service.image.as_deref() == Some(image))
        .map(|service| service.name.clone())
}

fn parse_trivy_severity(value: &str) -> Option<Severity> {
    match value.trim().to_ascii_uppercase().as_str() {
        "CRITICAL" => Some(Severity::Critical),
        "HIGH" => Some(Severity::High),
        "MEDIUM" => Some(Severity::Medium),
        "LOW" => Some(Severity::Low),
        _ => None,
    }
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
    }
}

fn slug(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push('_');
        }
    }

    let trimmed = out.trim_matches('_');
    if trimmed.is_empty() {
        String::from("image")
    } else {
        truncate(trimmed, 60)
    }
}

fn truncate(value: &str, max_len: usize) -> String {
    if value.len() <= max_len {
        return value.to_owned();
    }
    value.chars().take(max_len).collect()
}

#[derive(Debug, Clone, Deserialize)]
struct TrivyReport {
    #[serde(rename = "Results")]
    results: Option<Vec<TrivyResult>>,
}

#[derive(Debug, Clone, Deserialize)]
struct TrivyResult {
    #[serde(rename = "Target")]
    target: Option<String>,
    #[serde(rename = "Vulnerabilities")]
    vulnerabilities: Option<Vec<TrivyVulnerability>>,
}

#[derive(Debug, Clone, Deserialize)]
struct TrivyVulnerability {
    #[serde(rename = "VulnerabilityID")]
    vulnerability_id: Option<String>,
    #[serde(rename = "Severity")]
    severity: Option<String>,
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::*;

    fn temp_command(content: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should move forward")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "hostveil-trivy-test-command-{}-{nanos}",
            std::process::id()
        ));
        fs::write(&path, content).expect("test command should be written");
        let mut permissions = fs::metadata(&path)
            .expect("test command metadata should be available")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).expect("test command should be executable");
        path
    }

    #[test]
    fn maps_trivy_severities() {
        assert_eq!(parse_trivy_severity("CRITICAL"), Some(Severity::Critical));
        assert_eq!(parse_trivy_severity("high"), Some(Severity::High));
        assert_eq!(parse_trivy_severity("MEDIUM"), Some(Severity::Medium));
        assert_eq!(parse_trivy_severity("low"), Some(Severity::Low));
        assert_eq!(parse_trivy_severity("UNKNOWN"), None);
    }

    #[test]
    fn summarizes_trivy_report_into_single_finding_per_image() {
        let report: TrivyReport = serde_json::from_str(include_str!(
            "../../tests/fixtures/adapters/trivy-image-report.json"
        ))
        .expect("fixture should parse");

        let summary = summarize_report("demo:1.0", report).expect("should summarize");
        assert_eq!(summary.image, "demo:1.0");
        assert!(summary.total > 0);
        assert_eq!(summary.max_severity, Severity::Critical);

        let services = vec![ServiceSummary {
            name: String::from("demo"),
            image: Some(String::from("demo:1.0")),
        }];
        let finding = summary_to_finding(&summary, &services);

        assert_eq!(finding.source, Source::Trivy);
        assert_eq!(finding.scope, Scope::Image);
        assert_eq!(finding.axis, Axis::UpdateSupplyChainRisk);
        assert_eq!(finding.related_service.as_deref(), Some("demo"));
        assert!(finding.evidence.contains_key("vulnerabilities_total"));
        assert!(finding.evidence.contains_key("sample_ids"));
    }

    #[test]
    fn ignores_unmapped_severities_without_dropping_known_findings() {
        let report: TrivyReport = serde_json::from_str(
            r#"{
                "Results": [
                    {
                        "Target": "demo:1.0",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2026-9999",
                                "Severity": "UNKNOWN"
                            },
                            {
                                "VulnerabilityID": "CVE-2026-0002",
                                "Severity": "HIGH"
                            }
                        ]
                    }
                ]
            }"#,
        )
        .expect("fixture should parse");

        let summary = summarize_report("demo:1.0", report).expect("known findings should remain");

        assert_eq!(summary.total, 1);
        assert_eq!(summary.max_severity, Severity::High);
        assert_eq!(summary.sample_ids, vec![String::from("CVE-2026-0002")]);
    }

    #[test]
    fn keeps_adapter_available_when_only_some_image_scans_fail() {
        let mut output = TrivyScanOutput {
            status: AdapterStatus::Available,
            findings: Vec::new(),
            warnings: Vec::new(),
        };

        finalize_status_after_image_scans(
            &mut output,
            1,
            Some(String::from("registry denied access")),
        );

        assert_eq!(output.status, AdapterStatus::Available);
    }

    #[test]
    fn marks_adapter_failed_when_all_image_scans_fail() {
        let mut output = TrivyScanOutput {
            status: AdapterStatus::Available,
            findings: Vec::new(),
            warnings: Vec::new(),
        };

        finalize_status_after_image_scans(
            &mut output,
            0,
            Some(String::from("registry denied access")),
        );

        assert_eq!(
            output.status,
            AdapterStatus::Failed(String::from("registry denied access"))
        );
    }

    #[test]
    fn partial_image_timeout_preserves_successful_trivy_findings() {
        rust_i18n::set_locale("en");

        let command = temp_command(
            r#"#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "--version" ]]; then
  printf 'trivy test\n'
  exit 0
fi
image=""
for arg in "$@"; do
  if [[ "$arg" == "--cache-dir" ]]; then
    break
  fi
  image="$arg"
done
if [[ "$image" == "slow:1" ]]; then
  sleep 2
  exit 0
fi
cat <<'JSON'
{"Results":[{"Target":"fast:1","Vulnerabilities":[{"VulnerabilityID":"CVE-2026-0001","Severity":"HIGH"}]}]}
JSON
"#,
        );
        let command = command.display().to_string();
        let services = vec![
            ServiceSummary {
                name: String::from("fast"),
                image: Some(String::from("fast:1")),
            },
            ServiceSummary {
                name: String::from("slow"),
                image: Some(String::from("slow:1")),
            },
        ];

        let output = scan_with_commands(&services, &command, &command, Duration::from_millis(50));

        assert_eq!(output.status, AdapterStatus::Available);
        assert_eq!(output.findings.len(), 1);
        assert!(
            output
                .warnings
                .iter()
                .any(|warning| warning.contains("timed out after"))
        );

        let _ = fs::remove_file(command);
    }

    #[test]
    fn skips_when_no_image_targets_are_available() {
        let output = scan(&[]);

        assert_eq!(
            output.status,
            AdapterStatus::Skipped(
                t!("adapter.reason.no_image_targets", locale = "en").into_owned()
            )
        );
        assert!(output.findings.is_empty());
    }

    #[test]
    fn uses_vulnerability_only_scan_args() {
        assert_eq!(
            trivy_image_args("demo:1.0"),
            [
                "image",
                "--quiet",
                "--format",
                "json",
                "--scanners",
                "vuln",
                "demo:1.0",
            ]
        );
    }

    #[test]
    fn detect_trivy_reports_missing_for_unknown_binary() {
        let status = detect_trivy_with_command("hostveil-nonexistent-trivy");
        assert_eq!(status, TrivyAvailability::Missing);
    }

    #[test]
    fn detect_trivy_reports_failed_for_non_zero_command() {
        let status = detect_trivy_with_command("false");
        assert!(matches!(status, TrivyAvailability::Failed(_)));
    }

    #[test]
    fn detect_trivy_reports_available_for_true_command() {
        let status = detect_trivy_with_command("true");
        assert_eq!(status, TrivyAvailability::Available);
    }
}
