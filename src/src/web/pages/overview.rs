#![cfg(feature = "web")]

use std::collections::BTreeMap;

use axum::extract::State;
use axum::response::Html;
use rust_i18n::t;

use crate::domain::{AdapterStatus, Axis, Severity};
use crate::web::state::AppState;

pub async fn overview_page(State(state): State<AppState>) -> Html<String> {
    let scan_result = state.scan_result.read().expect("lock poisoned");

    let score = scan_result.score_report.overall;
    let score_class = if score >= 80 {
        "score-good"
    } else if score >= 50 {
        "score-warn"
    } else {
        "score-bad"
    };

    let total_findings = scan_result.findings.len();
    let severity_counts = &scan_result.score_report.severity_counts;
    let axis_scores = &scan_result.score_report.axis_scores;
    let warnings = &scan_result.metadata.warnings;
    let adapters = &scan_result.metadata.adapters;
    let services = &scan_result.metadata.services;

    let mut html = String::new();

    // Score + Severity counts
    html.push_str(&format!(
        r#"<div class="grid grid-3" style="margin-bottom:24px">
  <div class="card" style="text-align:center">
    <div class="score-circle {score_class}">{score}</div>
    <div class="score-label">{}</div>
  </div>
  <div class="card">
    <div class="card-title">{}</div>
    <div style="display:flex;flex-direction:column;gap:8px">
{}
    </div>
  </div>
  <div class="card">
    <div class="card-title">{}</div>
    <div class="stat-value">{}</div>
    <div class="stat-label">{}</div>
  </div>
</div>
"#,
        t!("web.overview.overall_score"),
        t!("web.overview.findings_by_severity"),
        severity_rows(severity_counts),
        t!("web.overview.total_findings"),
        total_findings,
        t!("web.overview.across_services", n = services.len()),
    ));

    // Axis scores
    html.push_str(&format!(
        r#"
<div class="card" style="margin-bottom:24px">
  <div class="card-title">{}</div>
 {}
</div>
"#,
        t!("web.overview.axis_scores"),
        axis_score_rows(axis_scores),
    ));

    // Warnings
    if !warnings.is_empty() {
        html.push_str(&format!(
            r#"
<div class="card" style="margin-bottom:24px;border-color:var(--medium)">
  <div class="card-title" style="color:var(--medium)">&#9888; {}</div>
 {}
</div>
"#,
            t!("web.overview.warnings_count", n = warnings.len()),
            warnings
                .iter()
                .map(|w| format!(
                    r#"<div style="padding:4px 0;font-size:13px;color:var(--medium)">{w}</div>"#
                ))
                .collect::<String>(),
        ));
    }

    // Adapter statuses
    if !adapters.is_empty() {
        html.push_str(&format!(
            r#"
<div class="card" style="margin-bottom:24px">
  <div class="card-title">{}</div>
  <table class="findings-table">
    <thead><tr><th>{}</th><th>{}</th></tr></thead>
    <tbody>
 {}
    </tbody>
  </table>
</div>
"#,
            t!("web.overview.adapter_status"),
            t!("web.overview.table_adapter"),
            t!("web.overview.table_status"),
            adapter_rows(adapters),
        ));
    }

    // Services
    if !services.is_empty() {
        html.push_str(&format!(
            r#"
<div class="card">
  <div class="card-title">{}</div>
  <table class="findings-table">
    <thead><tr><th>{}</th><th>{}</th></tr></thead>
    <tbody>
 {}
    </tbody>
  </table>
</div>
"#,
            t!("web.overview.services"),
            t!("web.overview.table_service"),
            t!("web.overview.table_image"),
            services
                .iter()
                .map(|s| format!(
                    r#"<tr><td>{}</td><td style="color:var(--text-secondary)">{}</td></tr>"#,
                    html_escape(&s.name),
                    s.image
                        .as_deref()
                        .map(html_escape)
                        .unwrap_or_else(|| String::from("—")),
                ))
                .collect::<String>(),
        ));
    }

    Html(html)
}

fn severity_rows(counts: &BTreeMap<Severity, usize>) -> String {
    let mut rows = String::new();
    for (severity, count) in [
        (
            Severity::Critical,
            counts.get(&Severity::Critical).copied().unwrap_or(0),
        ),
        (
            Severity::High,
            counts.get(&Severity::High).copied().unwrap_or(0),
        ),
        (
            Severity::Medium,
            counts.get(&Severity::Medium).copied().unwrap_or(0),
        ),
        (
            Severity::Low,
            counts.get(&Severity::Low).copied().unwrap_or(0),
        ),
    ] {
        let cls = severity.as_key();
        rows.push_str(&format!(r#"<div style="display:flex;justify-content:space-between;align-items:center"><span><span class="severity-dot dot-{cls}"></span> {sev}</span><span style="font-weight:600;color:var(--text-bright)">{count}</span></div>"#,
            sev = severity.as_key(),
        ));
    }
    rows
}

fn axis_score_rows(scores: &BTreeMap<Axis, u8>) -> String {
    let mut rows = String::new();
    for axis in Axis::ALL {
        let score = scores.get(&axis).copied().unwrap_or(100);
        let bar_color = if score >= 80 {
            "var(--success)"
        } else if score >= 50 {
            "var(--medium)"
        } else {
            "var(--critical)"
        };
        rows.push_str(&format!(r#"<div style="margin-bottom:14px"><div style="display:flex;justify-content:space-between;font-size:13px;margin-bottom:4px"><span>{axis}</span><span style="color:var(--text-bright);font-weight:600">{score}</span></div><div class="score-bar"><div class="score-bar-fill" style="width:{score}%;background:{bar_color}"></div></div></div>"#,
            axis = axis_label(axis),
        ));
    }
    rows
}

fn axis_label(axis: Axis) -> String {
    match axis {
        Axis::SensitiveData => t!("web.axis.sensitive_data").into_owned(),
        Axis::ExcessivePermissions => t!("web.axis.excessive_permissions").into_owned(),
        Axis::UnnecessaryExposure => t!("web.axis.unnecessary_exposure").into_owned(),
        Axis::UpdateSupplyChainRisk => t!("web.axis.update_supply_chain").into_owned(),
        Axis::HostHardening => t!("web.axis.host_hardening").into_owned(),
    }
}

fn adapter_status_class(status: &AdapterStatus) -> &'static str {
    match status {
        AdapterStatus::Available => "success",
        AdapterStatus::Pending => "",
        AdapterStatus::Missing => "critical",
        AdapterStatus::Skipped(_) => "",
        AdapterStatus::Failed(_) => "high",
    }
}

fn adapter_status_label(status: &AdapterStatus) -> String {
    match status {
        AdapterStatus::Available => t!("web.adapter.available").into_owned(),
        AdapterStatus::Pending => t!("web.adapter.pending").into_owned(),
        AdapterStatus::Missing => t!("web.adapter.missing").into_owned(),
        AdapterStatus::Skipped(reason) => {
            t!("web.adapter.skipped_reason", reason = reason).into_owned()
        }
        AdapterStatus::Failed(detail) => {
            t!("web.adapter.failed_detail", detail = detail).into_owned()
        }
    }
}

fn adapter_rows(adapters: &BTreeMap<String, AdapterStatus>) -> String {
    let mut rows = String::new();
    for (name, status) in adapters {
        let cls = adapter_status_class(status);
        let label = adapter_status_label(status);
        rows.push_str(&format!(r#"<tr><td style="text-transform:capitalize;font-weight:500">{name}</td><td><span style="color:var(--{cls})">{label}</span></td></tr>"#,
            cls = if cls.is_empty() { "text-secondary" } else { cls },
        ));
    }
    rows
}

pub(crate) fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
