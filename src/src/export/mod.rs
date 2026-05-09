use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::to_string_pretty;

use crate::domain::{Axis, Finding, ScanResult, ScoreReport, Severity};
use crate::i18n;

const JSON_SCHEMA_VERSION: &str = "0.16.0";
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

pub fn scan_result_markdown(scan_result: &ScanResult) -> String {
    scan_result_markdown_for_locale(scan_result, &i18n::current_locale())
}

fn scan_result_markdown_for_locale(scan_result: &ScanResult, locale: &str) -> String {
    let report = &scan_result.score_report;
    let mut output = String::new();

    output.push_str(&format!("# {}\n\n", report_title(locale)));
    output.push_str(&format!(
        "**{}: {}/100** | **{}: {}** | **{}: {}**\n\n",
        report_summary_score(locale),
        report.overall,
        report_summary_findings(locale),
        scan_result.findings.len(),
        report_summary_services(locale),
        scan_result.metadata.service_count,
    ));

    output.push_str(&format!("## {}\n\n", report_score_breakdown(locale)));
    output.push_str(&format!(
        "| {} | {} |\n|------|-------|\n",
        report_axis_column(locale),
        report_score_column(locale),
    ));
    for axis in Axis::ALL {
        if let Some(&score) = report.axis_scores.get(&axis) {
            output.push_str(&format!("| {} | {} |\n", axis_label(axis, locale), score));
        }
    }
    output.push('\n');

    let mut severity_groups: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
    for severity in Severity::ALL {
        severity_groups.insert(severity.as_key(), Vec::new());
    }
    for finding in &scan_result.findings {
        let key = finding.severity.as_key();
        if let Some(group) = severity_groups.get_mut(key) {
            group.push(finding);
        }
    }

    output.push_str(&format!("## {}\n\n", report_findings_heading(locale)));
    for severity in Severity::ALL {
        let key = severity.as_key();
        let group = &severity_groups[key];
        if group.is_empty() {
            continue;
        }
        output.push_str(&format!(
            "### {} ({})\n\n",
            severity_label(severity, locale),
            group.len()
        ));
        output.push_str(&format!(
            "| {} | {} | {} |\n|---|---|---|\n",
            report_id_column(locale),
            report_subject_column(locale),
            report_title_column(locale),
        ));
        for finding in group {
            output.push_str(&format!(
                "| `{}` | {} | {} |\n",
                finding.id,
                md_escape(&finding.subject),
                md_escape(&finding.title),
            ));
        }
        output.push('\n');
    }

    if !scan_result.metadata.warnings.is_empty() {
        output.push_str(&format!("## {}\n\n", report_warnings_heading(locale)));
        for warning in &scan_result.metadata.warnings {
            output.push_str(&format!("- {}\n", md_escape(warning)));
        }
        output.push('\n');
    }

    output.push_str(&format!("---\n*{}*\n", report_generated_by(locale),));

    output
}

fn md_escape(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

fn severity_label(severity: Severity, locale: &str) -> String {
    match severity {
        Severity::Critical => severity_critical(locale),
        Severity::High => severity_high(locale),
        Severity::Medium => severity_medium(locale),
        Severity::Low => severity_low(locale),
    }
}

fn axis_label(axis: Axis, locale: &str) -> String {
    match axis {
        Axis::SensitiveData => axis_sensitive_data(locale),
        Axis::ExcessivePermissions => axis_permissions(locale),
        Axis::UnnecessaryExposure => axis_exposure(locale),
        Axis::UpdateSupplyChainRisk => axis_updates(locale),
        Axis::HostHardening => axis_host_hardening(locale),
    }
}

pub fn scan_result_html(scan_result: &ScanResult) -> String {
    scan_result_html_for_locale(scan_result, &i18n::current_locale())
}

fn scan_result_html_for_locale(scan_result: &ScanResult, locale: &str) -> String {
    let report = &scan_result.score_report;
    let score_color = if report.overall >= 80 {
        "#9ece6a"
    } else if report.overall >= 50 {
        "#e0af68"
    } else {
        "#f7768e"
    };
    let lang = report_lang(locale);

    let mut html = String::new();
    html.push_str(&format!(
        "<!DOCTYPE html>\n<html lang=\"{lang}\">\n<head>\n"
    ));
    html.push_str("<meta charset=\"utf-8\">\n");
    html.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    html.push_str(&format!(
        "<title>{}</title>\n",
        html_escape(&report_title(locale))
    ));
    html.push_str("<style>\n");
    html.push_str(":root{--bg:#1a1b26;--fg:#c0caf5;--border:#24283b;--accent:#7aa2f7;--green:#9ece6a;--yellow:#e0af68;--red:#f7768e;--muted:#565f89}\n");
    html.push_str("*{box-sizing:border-box;margin:0;padding:0}\n");
    html.push_str("body{font-family:system-ui,monospace;background:var(--bg);color:var(--fg);line-height:1.6;padding:2rem;max-width:960px;margin:0 auto}\n");
    html.push_str("h1{color:var(--accent);margin-bottom:.5rem;font-size:1.5rem}\n");
    html.push_str("h2{color:var(--accent);margin:2rem 0 .5rem;font-size:1.2rem;border-bottom:1px solid var(--border);padding-bottom:.25rem}\n");
    html.push_str("h3{color:var(--fg);margin:1.5rem 0 .5rem;font-size:1rem}\n");
    html.push_str(".score-badge{display:inline-block;font-size:2.5rem;font-weight:bold;padding:.5rem 1.5rem;border-radius:.5rem;margin:1rem 0}\n");
    html.push_str(".meta{color:var(--muted);margin-bottom:1rem}\n");
    html.push_str("table{width:100%;border-collapse:collapse;margin:.5rem 0 1.5rem}\n");
    html.push_str(
        "th,td{padding:.5rem .75rem;text-align:left;border-bottom:1px solid var(--border)}\n",
    );
    html.push_str("th{color:var(--muted);font-weight:600;font-size:.85rem}\n");
    html.push_str("td{font-size:.9rem}\n");
    html.push_str("tr:hover{background:rgba(122,162,247,.05)}\n");
    html.push_str(".crit{color:var(--red)}\n.high{color:var(--yellow)}\n.medium{color:var(--muted)}\n.low{color:var(--fg)}\n");
    html.push_str("footer{text-align:center;color:var(--muted);margin-top:3rem;font-size:.8rem;border-top:1px solid var(--border);padding-top:1rem}\n");
    html.push_str("</style>\n</head>\n<body>\n");

    html.push_str(&format!(
        "<h1>{}</h1>\n",
        html_escape(&report_title(locale))
    ));
    html.push_str(&format!(
        "<p class=\"meta\">{}: {} &middot; {}: {} &middot; v{}</p>\n",
        html_escape(&report_summary_services(locale)),
        scan_result.metadata.service_count,
        html_escape(&report_summary_findings(locale)),
        scan_result.findings.len(),
        env!("CARGO_PKG_VERSION")
    ));

    html.push_str(&format!(
        "<div class=\"score-badge\" style=\"background:{}22;color:{}\">{}<span style=\"font-size:1rem\">/100</span></div>\n",
        score_color, score_color, report.overall,
    ));

    html.push_str(&format!(
        "<h2>{}</h2>\n<table>\n<tr><th>{}</th><th>{}</th></tr>\n",
        html_escape(&report_score_breakdown(locale)),
        html_escape(&report_axis_column(locale)),
        html_escape(&report_score_column(locale)),
    ));
    for axis in Axis::ALL {
        if let Some(&score) = report.axis_scores.get(&axis) {
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td></tr>\n",
                html_axis_label(axis, locale),
                score,
            ));
        }
    }
    html.push_str("</table>\n");

    let mut severity_groups: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
    for severity in Severity::ALL {
        severity_groups.insert(severity.as_key(), Vec::new());
    }
    for finding in &scan_result.findings {
        let key = finding.severity.as_key();
        if let Some(group) = severity_groups.get_mut(key) {
            group.push(finding);
        }
    }

    html.push_str(&format!(
        "<h2>{}</h2>\n",
        html_escape(&report_findings_heading(locale))
    ));
    for severity in Severity::ALL {
        let key = severity.as_key();
        let group = &severity_groups[key];
        if group.is_empty() {
            continue;
        }
        let severity_class = match severity {
            Severity::Critical => "crit",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
        };
        html.push_str(&format!(
            "<h3 class=\"{severity_class}\">{}</h3>\n<table>\n<tr><th>{}</th><th>{}</th><th>{}</th></tr>\n",
            html_severity_label(severity, locale),
            html_escape(&report_id_column(locale)),
            html_escape(&report_subject_column(locale)),
            html_escape(&report_title_column(locale)),
        ));
        for finding in group {
            html.push_str(&format!(
                "<tr><td><code>{}</code></td><td>{}</td><td>{}</td></tr>\n",
                finding.id,
                html_escape(&finding.subject),
                html_escape(&finding.title),
            ));
        }
        html.push_str("</table>\n");
    }

    if !scan_result.metadata.warnings.is_empty() {
        html.push_str(&format!(
            "<h2>{}</h2>\n<ul>\n",
            html_escape(&report_warnings_heading(locale))
        ));
        for warning in &scan_result.metadata.warnings {
            html.push_str(&format!("<li>{}</li>\n", html_escape(warning)));
        }
        html.push_str("</ul>\n");
    }

    html.push_str(&format!(
        "<footer>{}</footer>\n</body>\n</html>\n",
        html_escape(&report_generated_by(locale))
    ));

    html
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn html_axis_label(axis: Axis, locale: &str) -> String {
    match axis {
        Axis::SensitiveData => axis_sensitive_data(locale),
        Axis::ExcessivePermissions => axis_permissions(locale),
        Axis::UnnecessaryExposure => axis_exposure(locale),
        Axis::UpdateSupplyChainRisk => axis_updates(locale),
        Axis::HostHardening => axis_host_hardening(locale),
    }
}

fn html_severity_label(severity: Severity, locale: &str) -> String {
    match severity {
        Severity::Critical => severity_critical(locale),
        Severity::High => severity_high(locale),
        Severity::Medium => severity_medium(locale),
        Severity::Low => severity_low(locale),
    }
}

fn report_lang(locale: &str) -> &'static str {
    crate::i18n::parse_supported_locale(locale).unwrap_or(crate::i18n::DEFAULT_LOCALE)
}

fn report_title(locale: &str) -> String {
    match report_lang(locale) {
        "ko" => t!("app.report.title", locale = "ko").into_owned(),
        _ => t!("app.report.title", locale = "en").into_owned(),
    }
}

fn report_summary_score(locale: &str) -> String {
    match report_lang(locale) {
        "ko" => t!("app.report.summary_score", locale = "ko").into_owned(),
        _ => t!("app.report.summary_score", locale = "en").into_owned(),
    }
}

fn report_summary_findings(locale: &str) -> String {
    match report_lang(locale) {
        "ko" => t!("app.report.summary_findings", locale = "ko").into_owned(),
        _ => t!("app.report.summary_findings", locale = "en").into_owned(),
    }
}

fn report_summary_services(locale: &str) -> String {
    match report_lang(locale) {
        "ko" => t!("app.report.summary_services", locale = "ko").into_owned(),
        _ => t!("app.report.summary_services", locale = "en").into_owned(),
    }
}

fn report_score_breakdown(locale: &str) -> String {
    match report_lang(locale) {
        "ko" => t!("app.report.score_breakdown", locale = "ko").into_owned(),
        _ => t!("app.report.score_breakdown", locale = "en").into_owned(),
    }
}

fn report_findings_heading(locale: &str) -> String {
    match report_lang(locale) {
        "ko" => t!("app.report.findings_heading", locale = "ko").into_owned(),
        _ => t!("app.report.findings_heading", locale = "en").into_owned(),
    }
}

fn report_warnings_heading(locale: &str) -> String {
    match report_lang(locale) {
        "ko" => t!("app.report.warnings_heading", locale = "ko").into_owned(),
        _ => t!("app.report.warnings_heading", locale = "en").into_owned(),
    }
}

fn report_axis_column(locale: &str) -> String {
    match report_lang(locale) {
        "ko" => t!("app.report.axis_column", locale = "ko").into_owned(),
        _ => t!("app.report.axis_column", locale = "en").into_owned(),
    }
}

fn report_score_column(locale: &str) -> String {
    match report_lang(locale) {
        "ko" => t!("app.report.score_column", locale = "ko").into_owned(),
        _ => t!("app.report.score_column", locale = "en").into_owned(),
    }
}

fn report_id_column(locale: &str) -> String {
    match report_lang(locale) {
        "ko" => t!("app.report.id_column", locale = "ko").into_owned(),
        _ => t!("app.report.id_column", locale = "en").into_owned(),
    }
}

fn report_subject_column(locale: &str) -> String {
    match report_lang(locale) {
        "ko" => t!("app.report.subject_column", locale = "ko").into_owned(),
        _ => t!("app.report.subject_column", locale = "en").into_owned(),
    }
}

fn report_title_column(locale: &str) -> String {
    match report_lang(locale) {
        "ko" => t!("app.report.title_column", locale = "ko").into_owned(),
        _ => t!("app.report.title_column", locale = "en").into_owned(),
    }
}

fn report_generated_by(locale: &str) -> String {
    match report_lang(locale) {
        "ko" => t!(
            "app.report.generated_by",
            locale = "ko",
            version = env!("CARGO_PKG_VERSION")
        )
        .into_owned(),
        _ => t!(
            "app.report.generated_by",
            locale = "en",
            version = env!("CARGO_PKG_VERSION")
        )
        .into_owned(),
    }
}

fn severity_critical(locale: &str) -> String {
    match report_lang(locale) {
        "ko" => t!("severity.critical", locale = "ko").into_owned(),
        _ => t!("severity.critical", locale = "en").into_owned(),
    }
}

fn severity_high(locale: &str) -> String {
    match report_lang(locale) {
        "ko" => t!("severity.high", locale = "ko").into_owned(),
        _ => t!("severity.high", locale = "en").into_owned(),
    }
}

fn severity_medium(locale: &str) -> String {
    match report_lang(locale) {
        "ko" => t!("severity.medium", locale = "ko").into_owned(),
        _ => t!("severity.medium", locale = "en").into_owned(),
    }
}

fn severity_low(locale: &str) -> String {
    match report_lang(locale) {
        "ko" => t!("severity.low", locale = "ko").into_owned(),
        _ => t!("severity.low", locale = "en").into_owned(),
    }
}

fn axis_sensitive_data(locale: &str) -> String {
    match report_lang(locale) {
        "ko" => t!("axis.sensitive_data", locale = "ko").into_owned(),
        _ => t!("axis.sensitive_data", locale = "en").into_owned(),
    }
}

fn axis_permissions(locale: &str) -> String {
    match report_lang(locale) {
        "ko" => t!("axis.permissions", locale = "ko").into_owned(),
        _ => t!("axis.permissions", locale = "en").into_owned(),
    }
}

fn axis_exposure(locale: &str) -> String {
    match report_lang(locale) {
        "ko" => t!("axis.exposure", locale = "ko").into_owned(),
        _ => t!("axis.exposure", locale = "en").into_owned(),
    }
}

fn axis_updates(locale: &str) -> String {
    match report_lang(locale) {
        "ko" => t!("axis.updates", locale = "ko").into_owned(),
        _ => t!("axis.updates", locale = "en").into_owned(),
    }
}

fn axis_host_hardening(locale: &str) -> String {
    match report_lang(locale) {
        "ko" => t!("axis.host_hardening", locale = "ko").into_owned(),
        _ => t!("axis.host_hardening", locale = "en").into_owned(),
    }
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

        assert_eq!(json["version"].as_str().unwrap(), "0.16.0");
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

        assert_eq!(json["version"].as_str().unwrap(), "0.16.0");
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

    use super::{scan_result_html_for_locale, scan_result_markdown_for_locale};

    #[test]
    fn markdown_includes_header_and_score() {
        let result = ScanResult::default();
        let md = scan_result_markdown_for_locale(&result, "en");

        assert!(md.contains("# hostveil Security Scan Report"));
        assert!(md.contains("**Score: 100/100**"));
        assert!(md.contains("## Score Breakdown"));
        assert!(md.contains("## Findings"));
    }

    #[test]
    fn markdown_groups_findings_by_severity() {
        let mut result = ScanResult::default();
        result.findings.push(test_finding(
            "test.crit",
            Scope::Service,
            Source::NativeCompose,
            "web",
            Some("web"),
        ));
        result.findings.push(test_finding(
            "test.low",
            Scope::Service,
            Source::NativeCompose,
            "api",
            Some("web"),
        ));
        result.score_report.overall = 50;

        let md = scan_result_markdown_for_locale(&result, "en");

        assert!(md.contains("**Score: 50/100**"));
        assert!(md.contains("### High"));
        assert!(md.contains("`test.crit`"));
    }

    #[test]
    fn markdown_includes_warnings() {
        let mut result = ScanResult::default();
        result.metadata.warnings.push("test warning".into());

        let md = scan_result_markdown_for_locale(&result, "en");
        assert!(md.contains("## Warnings"));
        assert!(md.contains("test warning"));
    }

    #[test]
    fn markdown_escapes_pipe_characters() {
        let mut result = ScanResult::default();
        let mut finding = test_finding(
            "test.pipe",
            Scope::Service,
            Source::NativeCompose,
            "foo|bar",
            Some("web"),
        );
        finding.title = "test | title".into();
        result.findings.push(finding);

        let md = scan_result_markdown_for_locale(&result, "en");
        assert!(md.contains("foo\\|bar"));
        assert!(md.contains("test \\| title"));
    }

    #[test]
    fn markdown_localizes_headings_for_korean() {
        let result = ScanResult::default();
        let md = scan_result_markdown_for_locale(&result, "ko");

        assert!(md.contains("# hostveil 보안 스캔 리포트"));
        assert!(md.contains("**점수: 100/100**"));
        assert!(md.contains("## 점수 상세"));
        assert!(md.contains("## 발견 항목"));
    }

    #[test]
    fn html_includes_doctype_and_structure() {
        let result = ScanResult::default();
        let html = scan_result_html_for_locale(&result, "en");

        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("<title>hostveil Security Scan Report</title>"));
        assert!(html.contains("<html lang=\"en\">"));
        assert!(html.contains("Score Breakdown"));
        assert!(html.contains("Findings"));
        assert!(html.contains("</html>"));
    }

    #[test]
    fn html_shows_score_with_color() {
        let mut result = ScanResult::default();
        result.score_report.overall = 42;
        let html = scan_result_html_for_locale(&result, "en");

        assert!(html.contains("42"));
        assert!(html.contains("/100"));
        assert!(html.contains("#f7768e")); // red for low score
    }

    #[test]
    fn html_escapes_special_characters() {
        let mut result = ScanResult::default();
        let mut finding = test_finding(
            "test.escape",
            Scope::Service,
            Source::NativeCompose,
            "<script>alert('xss')</script>",
            Some("web"),
        );
        finding.title = "bad & stuff".into();
        result.findings.push(finding);

        let html = scan_result_html_for_locale(&result, "en");
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(!html.contains("bad & stuff"));
        assert!(html.contains("bad &amp; stuff"));
    }

    #[test]
    fn html_includes_warnings_section() {
        let mut result = ScanResult::default();
        result.metadata.warnings.push("test warning".into());
        let html = scan_result_html_for_locale(&result, "en");

        assert!(html.contains("Warnings"));
        assert!(html.contains("test warning"));
    }

    #[test]
    fn html_localizes_title_and_lang_for_korean() {
        let result = ScanResult::default();
        let html = scan_result_html_for_locale(&result, "ko");

        assert!(html.contains("<html lang=\"ko\">"));
        assert!(html.contains("<title>hostveil 보안 스캔 리포트</title>"));
        assert!(html.contains("<h2>점수 상세</h2>"));
        assert!(html.contains("<h2>발견 항목</h2>"));
    }
}
