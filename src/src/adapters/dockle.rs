use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;
use std::time::Duration;

use serde::Deserialize;

use crate::adapters::command;
use crate::domain::{
    AdapterStatus, Axis, Finding, RemediationKind, Scope, ServiceSummary, Severity, Source,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockleScanOutput {
    pub status: AdapterStatus,
    pub findings: Vec<Finding>,
    pub warnings: Vec<String>,
}

pub fn scan(services: &[ServiceSummary]) -> DockleScanOutput {
    scan_with_commands(
        services,
        "dockle",
        "dockle",
        command::DEFAULT_ADAPTER_TIMEOUT,
    )
}

fn scan_with_commands(
    services: &[ServiceSummary],
    detect_command: &str,
    scan_command: &str,
    timeout: Duration,
) -> DockleScanOutput {
    let mut output = DockleScanOutput {
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

    match detect_dockle_with_command_and_timeout(detect_command, timeout) {
        DockleAvailability::Missing => {
            output.status = AdapterStatus::Missing;
            return output;
        }
        DockleAvailability::Available => {
            output.status = AdapterStatus::Available;
        }
        DockleAvailability::Failed(detail) => {
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
                output.warnings.push(crate::i18n::tr_adapter_scan_failed(
                    "Dockle", &image, &error,
                ));
            }
        }
    }

    finalize_status_after_image_scans(&mut output, successful_scans, first_scan_error);

    output
}

fn finalize_status_after_image_scans(
    output: &mut DockleScanOutput,
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
enum DockleAvailability {
    Available,
    Missing,
    Failed(String),
}

#[cfg(test)]
fn detect_dockle_with_command(command_name: &str) -> DockleAvailability {
    detect_dockle_with_command_and_timeout(command_name, command::DEFAULT_ADAPTER_TIMEOUT)
}

fn detect_dockle_with_command_and_timeout(
    command_name: &str,
    timeout: Duration,
) -> DockleAvailability {
    let mut command = Command::new(command_name);
    command.arg("--version").env("NO_COLOR", "1");
    let output = command::run_with_timeout(command, timeout);

    match output {
        Ok(output) if output.status.success() => DockleAvailability::Available,
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            DockleAvailability::Failed(truncate(stderr.trim(), 200))
        }
        Err(error) if error.is_not_found() => DockleAvailability::Missing,
        Err(error) => DockleAvailability::Failed(truncate(&error.detail(), 200)),
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
struct DockleImageSummary {
    image: String,
    total: usize,
    counts: BTreeMap<DockleLevel, usize>,
    max_level: DockleLevel,
    sample_codes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum DockleLevel {
    Fatal,
    Warn,
    Info,
}

fn scan_image_with_command(
    command_name: &str,
    image: &str,
    timeout: Duration,
) -> Result<Option<DockleImageSummary>, String> {
    let mut command = Command::new(command_name);
    command.args(dockle_image_args(image)).env("NO_COLOR", "1");
    let output = command::run_with_timeout(command, timeout).map_err(|error| error.detail())?;

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

    let report: DockleReport = serde_json::from_slice(&output.stdout)
        .map_err(|error| crate::i18n::tr_adapter_json_parse_failed("Dockle", &error.to_string()))?;

    Ok(summarize_report(image, report))
}

fn dockle_image_args(image: &str) -> [&str; 5] {
    ["--format", "json", "--exit-code", "0", image]
}

fn summarize_report(image: &str, report: DockleReport) -> Option<DockleImageSummary> {
    let mut counts = BTreeMap::from([
        (DockleLevel::Fatal, 0_usize),
        (DockleLevel::Warn, 0_usize),
        (DockleLevel::Info, 0_usize),
    ]);
    let mut sample_codes = Vec::new();
    let mut max_level: Option<DockleLevel> = None;

    for detail in report.details.unwrap_or_default() {
        let Some(level) = detail.level.as_deref().and_then(parse_dockle_level) else {
            continue;
        };

        *counts.entry(level).or_insert(0) += 1;

        if max_level.is_none_or(|current| level_rank(level) < level_rank(current)) {
            max_level = Some(level);
        }

        if sample_codes.len() < 5
            && let Some(code) = detail.code
        {
            sample_codes.push(code);
        }
    }

    let total: usize = counts.values().sum();
    let max_level = max_level?;

    Some(DockleImageSummary {
        image: image.to_owned(),
        total,
        counts,
        max_level,
        sample_codes,
    })
}

fn parse_dockle_level(value: &str) -> Option<DockleLevel> {
    match value.trim().to_ascii_uppercase().as_str() {
        "FATAL" => Some(DockleLevel::Fatal),
        "WARN" => Some(DockleLevel::Warn),
        "INFO" => Some(DockleLevel::Info),
        _ => None,
    }
}

fn level_rank(level: DockleLevel) -> u8 {
    match level {
        DockleLevel::Fatal => 0,
        DockleLevel::Warn => 1,
        DockleLevel::Info => 2,
    }
}

fn dockle_level_severity(level: DockleLevel) -> Severity {
    match level {
        DockleLevel::Fatal => Severity::High,
        DockleLevel::Warn => Severity::Medium,
        DockleLevel::Info => Severity::Low,
    }
}

fn summary_to_finding(summary: &DockleImageSummary, services: &[ServiceSummary]) -> Finding {
    let related_service = related_service_for_image(&summary.image, services);

    let mut evidence = BTreeMap::new();
    evidence.insert(String::from("image"), summary.image.clone());
    evidence.insert(String::from("checks_total"), summary.total.to_string());
    evidence.insert(
        String::from("fatal"),
        summary
            .counts
            .get(&DockleLevel::Fatal)
            .copied()
            .unwrap_or_default()
            .to_string(),
    );
    evidence.insert(
        String::from("warn"),
        summary
            .counts
            .get(&DockleLevel::Warn)
            .copied()
            .unwrap_or_default()
            .to_string(),
    );
    evidence.insert(
        String::from("info"),
        summary
            .counts
            .get(&DockleLevel::Info)
            .copied()
            .unwrap_or_default()
            .to_string(),
    );
    if !summary.sample_codes.is_empty() {
        evidence.insert(
            String::from("sample_codes"),
            summary.sample_codes.join(", "),
        );
    }

    Finding {
        id: format!("dockle.image_best_practice.{}", slug(&summary.image)),
        axis: Axis::UpdateSupplyChainRisk,
        severity: dockle_level_severity(summary.max_level),
        scope: Scope::Image,
        source: Source::Dockle,
        subject: summary.image.clone(),
        related_service,
        title: t!("finding.dockle.image_best_practice.title").into_owned(),
        description: t!(
            "finding.dockle.image_best_practice.description",
            image = summary.image,
            count = summary.total
        )
        .into_owned(),
        why_risky: t!("finding.dockle.image_best_practice.why").into_owned(),
        how_to_fix: t!("finding.dockle.image_best_practice.fix").into_owned(),
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
struct DockleReport {
    #[serde(rename = "details")]
    details: Option<Vec<DockleDetail>>,
}

#[derive(Debug, Clone, Deserialize)]
struct DockleDetail {
    #[serde(rename = "code")]
    code: Option<String>,
    #[serde(rename = "level")]
    level: Option<String>,
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
            "hostveil-dockle-test-command-{}-{nanos}",
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
    fn maps_dockle_levels() {
        assert_eq!(parse_dockle_level("FATAL"), Some(DockleLevel::Fatal));
        assert_eq!(parse_dockle_level("warn"), Some(DockleLevel::Warn));
        assert_eq!(parse_dockle_level("INFO"), Some(DockleLevel::Info));
        assert_eq!(parse_dockle_level("PASS"), None);
    }

    #[test]
    fn summarizes_dockle_report_into_single_finding_per_image() {
        let report: DockleReport = serde_json::from_str(include_str!(
            "../../tests/fixtures/adapters/dockle-image-report.json"
        ))
        .expect("fixture should parse");

        let summary = summarize_report("demo:1.0", report).expect("should summarize");
        assert_eq!(summary.image, "demo:1.0");
        assert!(summary.total > 0);
        assert_eq!(summary.max_level, DockleLevel::Fatal);

        let services = vec![ServiceSummary {
            name: String::from("demo"),
            image: Some(String::from("demo:1.0")),
        }];
        let finding = summary_to_finding(&summary, &services);

        assert_eq!(finding.source, Source::Dockle);
        assert_eq!(finding.scope, Scope::Image);
        assert_eq!(finding.axis, Axis::UpdateSupplyChainRisk);
        assert_eq!(finding.related_service.as_deref(), Some("demo"));
        assert!(finding.evidence.contains_key("checks_total"));
        assert!(finding.evidence.contains_key("sample_codes"));
    }

    #[test]
    fn ignores_unmapped_levels_without_dropping_known_findings() {
        let report: DockleReport = serde_json::from_str(
            r#"{
                "details": [
                    {"code": "CIS-DI-0001", "level": "PASS"},
                    {"code": "DKL-DI-0005", "level": "WARN"}
                ]
            }"#,
        )
        .expect("fixture should parse");

        let summary = summarize_report("demo:1.0", report).expect("known findings should remain");

        assert_eq!(summary.total, 1);
        assert_eq!(summary.max_level, DockleLevel::Warn);
        assert_eq!(summary.sample_codes, vec![String::from("DKL-DI-0005")]);
    }

    #[test]
    fn keeps_adapter_available_when_only_some_image_scans_fail() {
        let mut output = DockleScanOutput {
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
        let mut output = DockleScanOutput {
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
    fn partial_image_timeout_preserves_successful_dockle_findings() {
        rust_i18n::set_locale("en");

        let command = temp_command(
            r#"#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "--version" ]]; then
  printf 'dockle test\n'
  exit 0
fi
image="${@: -1}"
if [[ "$image" == "slow:1" ]]; then
  sleep 2
  exit 0
fi
cat <<'JSON'
{"details":[{"code":"DKL-DI-0001","level":"WARN"}]}
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
    fn marks_adapter_failed_when_all_image_scans_timeout() {
        rust_i18n::set_locale("en");

        let command = temp_command(
            r#"#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "--version" ]]; then
  printf 'dockle test\n'
  exit 0
fi
sleep 2
exit 0
"#,
        );
        let command = command.display().to_string();
        let services = vec![
            ServiceSummary {
                name: String::from("slow_one"),
                image: Some(String::from("slow:1")),
            },
            ServiceSummary {
                name: String::from("slow_two"),
                image: Some(String::from("slow:2")),
            },
        ];

        let output = scan_with_commands(&services, &command, &command, Duration::from_millis(50));

        assert!(
            matches!(output.status, AdapterStatus::Failed(ref msg) if msg.contains("timed out after"))
        );
        assert!(output.findings.is_empty());
        assert_eq!(output.warnings.len(), 2);

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
    fn uses_json_scan_args_with_non_failing_exit_code() {
        assert_eq!(
            dockle_image_args("demo:1.0"),
            ["--format", "json", "--exit-code", "0", "demo:1.0",]
        );
    }

    #[test]
    fn detect_dockle_reports_missing_for_unknown_binary() {
        let status = detect_dockle_with_command("hostveil-nonexistent-dockle");
        assert_eq!(status, DockleAvailability::Missing);
    }

    #[test]
    fn detect_dockle_reports_failed_for_non_zero_command() {
        let status = detect_dockle_with_command("false");
        assert!(matches!(status, DockleAvailability::Failed(_)));
    }

    #[test]
    fn detect_dockle_reports_available_for_true_command() {
        let status = detect_dockle_with_command("true");
        assert_eq!(status, DockleAvailability::Available);
    }
}
