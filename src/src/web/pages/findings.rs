#![cfg(feature = "web")]

use axum::extract::{Path, Query, State};
use axum::response::Html;
use rust_i18n::t;
use serde::Deserialize;

use crate::domain::{Finding, RemediationKind, Severity, Source};
use crate::web::state::AppState;

use super::overview::html_escape;

#[derive(Deserialize)]
pub struct FindingsPageQuery {
    severity: Option<String>,
    source: Option<String>,
    search: Option<String>,
}

fn list_target() -> &'static str {
    "finding-list-content"
}

pub async fn findings_page(
    State(state): State<AppState>,
    Query(query): Query<FindingsPageQuery>,
) -> Html<String> {
    let scan_result = state.scan_result.read().expect("lock poisoned");

    let severity_filter = query.severity.as_deref().and_then(Severity::from_key);
    let source_filter = query.source.as_deref().and_then(parse_source);
    let search = query.search.as_deref().unwrap_or("").to_lowercase();

    let mut findings: Vec<&Finding> = scan_result.findings.iter().collect();

    findings.retain(|f| {
        severity_filter.is_none_or(|s| f.severity == s)
            && source_filter.is_none_or(|s| f.source == s)
            && (search.is_empty()
                || f.title.to_lowercase().contains(&search)
                || f.description.to_lowercase().contains(&search)
                || f.subject.to_lowercase().contains(&search))
    });

    findings.sort_by_key(|a| a.severity);

    let active_severity = query.severity.as_deref().unwrap_or("");
    let active_source = query.source.as_deref().unwrap_or("");
    let active_search = query.search.as_deref().unwrap_or("");

    let sev_selected = |v: &str| if active_severity == v { "selected" } else { "" };
    let src_selected = |v: &str| if active_source == v { "selected" } else { "" };

    let target = list_target();

    let mut html = String::new();

    // Filters row
    html.push_str("<div style=\"margin-bottom:20px\"><div style=\"display:flex;gap:12px;align-items:center;flex-wrap:wrap\">");

    // Severity select
    html.push_str(&format!(
        "<select style=\"background:var(--bg-hover);color:var(--text-primary);border:1px solid var(--border);border-radius:6px;padding:6px 10px;font-size:13px;outline:none;cursor:pointer\" \
         hx-get=\"/findings\" hx-target=\"{target}\" hx-push-url=\"true\" name=\"severity\">"
    ));
    html.push_str(&format!(
        "<option value=\"\" {s}>{}</option>",
        t!("web.findings.all_severities"),
        s = sev_selected("")
    ));
    let severity_options = [
        ("critical", t!("severity.critical")),
        ("high", t!("severity.high")),
        ("medium", t!("severity.medium")),
        ("low", t!("severity.low")),
    ];
    for (val, label) in &severity_options {
        html.push_str(&format!(
            "<option value=\"{val}\" {sel}>{label}</option>",
            sel = sev_selected(val)
        ));
    }
    html.push_str("</select>");

    // Source select
    html.push_str(&format!(
        "<select style=\"background:var(--bg-hover);color:var(--text-primary);border:1px solid var(--border);border-radius:6px;padding:6px 10px;font-size:13px;outline:none;cursor:pointer\" \
         hx-get=\"/findings\" hx-target=\"{target}\" hx-push-url=\"true\" name=\"source\">"
    ));
    html.push_str(&format!(
        "<option value=\"\" {s}>{}</option>",
        t!("web.findings.all_sources"),
        s = src_selected("")
    ));
    let source_options = [
        ("native_compose", t!("source.native_compose")),
        ("native_host", t!("source.native_host")),
        ("trivy", t!("source.trivy")),
        ("dockle", t!("source.dockle")),
        ("lynis", t!("source.lynis")),
        ("gitleaks", t!("source.gitleaks")),
    ];
    for (val, label) in &source_options {
        html.push_str(&format!(
            "<option value=\"{val}\" {sel}>{label}</option>",
            sel = src_selected(val)
        ));
    }
    html.push_str("</select>");

    // Search input
    let escaped_search = html_escape(active_search);
    html.push_str("<div style=\"position:relative;flex:1;max-width:300px\">");
    html.push_str(&format!(
        "<input style=\"background:var(--bg-hover);color:var(--text-primary);border:1px solid var(--border);border-radius:6px;padding:6px 10px;font-size:13px;width:100%;outline:none\" \
         type=\"search\" placeholder=\"{}\" name=\"search\" value=\"{escaped_search}\" \
         hx-get=\"/findings\" hx-trigger=\"keyup changed delay:300ms\" hx-target=\"{target}\" hx-push-url=\"true\">",
        t!("web.findings.search_placeholder"),
    ));
    html.push_str("</div></div></div>");

    // Findings table
    html.push_str(&format!("<div id=\"{target}\">"));
    html.push_str("<table class=\"findings-table\">");
    html.push_str(&format!(
        "<thead><tr>\
         <th>{}</th><th>{}</th><th>{}</th><th>{}</th><th>{}</th><th>{}</th>\
         </tr></thead><tbody>",
        t!("web.findings.table_severity"),
        t!("web.findings.table_title"),
        t!("web.findings.table_axis"),
        t!("web.findings.table_source"),
        t!("web.findings.table_service"),
        t!("web.findings.table_fix"),
    ));

    if findings.is_empty() {
        html.push_str(&format!("<tr><td colspan=\"6\" style=\"text-align:center;padding:40px;color:var(--text-secondary)\">{}</td></tr>", t!("web.findings.empty")));
    } else {
        for finding in &findings {
            let sev = finding.severity.as_key();
            let src = finding.source.as_key();
            let axis = finding.axis.as_key();
            let id = html_escape(&finding.id);
            let title = html_escape(&finding.title);
            let service = finding
                .related_service
                .as_deref()
                .map(html_escape)
                .unwrap_or_else(|| String::from("&mdash;"));
            let fix_badge = fix_badge(finding.remediation);

            html.push_str(&format!(
                "<tr style=\"cursor:pointer\" onclick=\"window.location.href='/findings/{id}'\">"
            ));
            html.push_str(&format!("<td><span class=\"severity-badge {sev}\"><span class=\"severity-dot dot-{sev}\"></span>{sev}</span></td>"));
            html.push_str(&format!("<td style=\"max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap\">{title}</td>"));
            html.push_str(&format!(
                "<td style=\"color:var(--text-secondary)\">{axis}</td>"
            ));
            html.push_str(&format!(
                "<td style=\"color:var(--text-secondary)\">{src}</td>"
            ));
            html.push_str(&format!(
                "<td style=\"color:var(--text-secondary)\">{service}</td>"
            ));
            html.push_str(&format!("<td>{fix_badge}</td>"));
            html.push_str("</tr>");
        }
    }

    html.push_str("</tbody></table></div>");

    Html(html)
}

pub async fn finding_detail(State(state): State<AppState>, Path(id): Path<String>) -> Html<String> {
    let scan_result = state.scan_result.read().expect("lock poisoned");

    let finding = match scan_result.findings.iter().find(|f| f.id == id) {
        Some(f) => f,
        None => {
            return Html(format!(
                "<div style=\"text-align:center;padding:40px;color:var(--text-secondary)\">\
                 <h2>{}</h2>\
                 <p style=\"margin-top:8px\">{}</p>\
                 <a href=\"/findings\" style=\"color:var(--accent)\">{}</a></div>",
                t!("web.findings.not_found"),
                t!("web.findings.not_found_id", id = id),
                t!("web.findings.back_to_findings"),
            ));
        }
    };

    let html = render_finding_detail(finding);
    Html(html)
}

fn render_finding_detail(finding: &Finding) -> String {
    let sev_class = finding.severity.as_key();
    let id_esc = html_escape(&finding.id);
    let title = html_escape(&finding.title);
    let sev = finding.severity.as_key();
    let axis = finding.axis.as_key();
    let source = finding.source.as_key();
    let service = finding
        .related_service
        .as_deref()
        .map(|s| format!("{} {}", t!("web.findings.service_label"), html_escape(s)))
        .unwrap_or_default();
    let desc = html_escape(&finding.description);
    let why_risky = html_escape(&finding.why_risky);
    let how_to_fix = html_escape(&finding.how_to_fix);
    let remediation = remediation_label(finding.remediation);

    let mut html = String::new();

    // Back link
    html.push_str(&format!("<div style=\"margin-bottom:16px\"><a href=\"/findings\" style=\"color:var(--accent);font-size:13px\">&larr; {}</a></div>", t!("web.findings.back_to_findings")));

    // Header card
    html.push_str("<div class=\"card\" style=\"margin-bottom:20px\">");
    html.push_str("<div style=\"display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:16px\">");
    html.push_str(&format!("<div><h2 style=\"color:var(--text-bright);font-size:18px;font-weight:600;margin:0\">{title}</h2>"));
    html.push_str(&format!("<div style=\"display:flex;gap:8px;margin-top:8px\">\
                            <span class=\"severity-badge {sev_class}\">{sev}</span>\
                            <span style=\"font-size:12px;color:var(--text-secondary);padding:2px 0\">{axis} &middot; {source}</span></div>"));
    html.push_str(&format!("</div><div style=\"text-align:right;font-size:12px;color:var(--text-secondary)\">\
                            <div style=\"margin-bottom:4px\">ID: {id_esc}</div><div>{service}</div></div>"));
    html.push_str("</div></div>");

    // Description + Why Risky
    html.push_str(&format!(
        "<div class=\"grid grid-2\" style=\"margin-bottom:20px\">\
         <div class=\"card\"><div class=\"card-title\">{}</div>\
         <p style=\"font-size:13px;line-height:1.6\">{desc}</p></div>\
         <div class=\"card\"><div class=\"card-title\">{}</div>\
         <p style=\"font-size:13px;line-height:1.6\">{why_risky}</p></div></div>",
        t!("web.findings.description"),
        t!("web.findings.why_risky"),
    ));

    // How to Fix
    if !finding.how_to_fix.is_empty() {
        html.push_str(&format!(
            "<div class=\"card\" style=\"margin-bottom:20px;border-color:var(--accent)\">\
             <div class=\"card-title\" style=\"color:var(--accent)\">{}</div>\
             <p style=\"font-size:13px;line-height:1.6\">{how_to_fix}</p>\
             <div style=\"margin-top:12px\"><span style=\"font-size:12px;color:var(--text-secondary)\">{}</span>\
             <span class=\"severity-badge\" style=\"background:color-mix(in srgb, var(--accent) 15%, transparent);color:var(--accent)\">{remediation}</span></div></div>",
            t!("web.findings.how_to_fix"),
            t!("web.findings.remediation_label"),
        ));
    }

    // Evidence
    if !finding.evidence.is_empty() {
        html.push_str(&format!(
            "<div class=\"card\"><div class=\"card-title\">{}</div>",
            t!("web.findings.evidence")
        ));
        for (key, value) in &finding.evidence {
            let k = html_escape(key);
            let v = html_escape(value);
            html.push_str(&format!(
                "<div style=\"margin-bottom:8px;font-size:13px\"><strong style=\"color:var(--text-secondary)\">{k}:</strong> \
                 <code style=\"color:var(--text-bright);background:var(--bg-hover);padding:1px 6px;border-radius:3px\">{v}</code></div>"
            ));
        }
        html.push_str("</div>");
    }

    // Fix button
    let is_fixable = matches!(
        finding.remediation,
        RemediationKind::Auto | RemediationKind::Review
    );
    if is_fixable && finding.related_service.is_some() {
        html.push_str(&format!(
            "<div style=\"margin-top:20px;text-align:right\"><a href=\"/fix/{id_esc}\" class=\"btn btn-primary\">{}</a></div>",
            t!("web.findings.apply_fix"),
        ));
    }

    html
}

fn parse_source(s: &str) -> Option<Source> {
    match s {
        "native_compose" => Some(Source::NativeCompose),
        "native_host" => Some(Source::NativeHost),
        "trivy" => Some(Source::Trivy),
        "lynis" => Some(Source::Lynis),
        "dockle" => Some(Source::Dockle),
        "gitleaks" => Some(Source::Gitleaks),
        _ => None,
    }
}

fn fix_badge(remediation: RemediationKind) -> String {
    match remediation {
        RemediationKind::Auto => format!(
            "<span style=\"color:var(--success);font-size:12px\">{}</span>",
            t!("web.remediation.auto")
        ),
        RemediationKind::Review => format!(
            "<span style=\"color:var(--accent);font-size:12px\">{}</span>",
            t!("web.remediation.review")
        ),
        RemediationKind::Manual => format!(
            "<span style=\"color:var(--text-secondary);font-size:12px\">{}</span>",
            t!("web.remediation.manual")
        ),
    }
}

fn remediation_label(remediation: RemediationKind) -> String {
    match remediation {
        RemediationKind::Auto => t!("web.remediation.auto_safe").into_owned(),
        RemediationKind::Review => t!("web.remediation.review_guided").into_owned(),
        RemediationKind::Manual => t!("web.remediation.manual").into_owned(),
    }
}
