use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;

use serde::Deserialize;

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
    let mut output = TrivyScanOutput {
        status: AdapterStatus::Missing,
        findings: Vec::new(),
        warnings: Vec::new(),
    };

    match detect_trivy() {
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

    let images = dedup_images(services);
    if images.is_empty() {
        return output;
    }

    for image in images {
        match scan_image(&image) {
            Ok(Some(summary)) => {
                output.findings.push(summary_to_finding(&summary, services));
            }
            Ok(None) => {}
            Err(error) => {
                output.status = AdapterStatus::Failed(error.clone());
                output
                    .warnings
                    .push(format!("Trivy scan failed for {image}: {error}"));
            }
        }
    }

    output
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TrivyAvailability {
    Available,
    Missing,
    Failed(String),
}

fn detect_trivy() -> TrivyAvailability {
    let output = Command::new("trivy")
        .arg("--version")
        .env("NO_COLOR", "1")
        .output();

    match output {
        Ok(output) if output.status.success() => TrivyAvailability::Available,
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            TrivyAvailability::Failed(truncate(stderr.trim(), 200))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => TrivyAvailability::Missing,
        Err(error) => TrivyAvailability::Failed(truncate(&error.to_string(), 200)),
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

fn scan_image(image: &str) -> Result<Option<TrivyImageSummary>, String> {
    let output = Command::new("trivy")
        .args(["image", "--format", "json", image])
        .env("NO_COLOR", "1")
        .output()
        .map_err(|error| error.to_string())?;

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
        .map_err(|error| format!("failed to parse Trivy JSON: {error}"))?;

    Ok(summarize_report(image, report))
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
            let severity = vuln.severity.as_deref().and_then(parse_trivy_severity)?;

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
    use super::*;

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
}
