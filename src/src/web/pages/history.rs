#![cfg(feature = "web")]

use axum::extract::State;
use axum::response::Html;
use rust_i18n::t;

use crate::domain::Axis;
use crate::history;
use crate::web::state::AppState;

use super::overview::html_escape;

pub async fn history_page(State(state): State<AppState>) -> Html<String> {
    let scan_result = state.scan_result.read().expect("lock poisoned");

    let current_score = scan_result.score_report.overall;
    let current_findings = scan_result.findings.len();

    let scan_history = history::load();
    let entries = scan_history.trend(50);

    let mut html = String::new();

    // Current state
    html.push_str(&format!(
        "<div class=\"grid grid-3\" style=\"margin-bottom:24px\">\
         <div class=\"card\" style=\"text-align:center\"><div class=\"stat-value\">{}</div><div class=\"stat-label\">{}</div></div>\
         <div class=\"card\" style=\"text-align:center\"><div class=\"stat-value\" style=\"color:var(--high)\">{}</div><div class=\"stat-label\">{}</div></div>\
         <div class=\"card\" style=\"text-align:center\"><div class=\"stat-value\">{}</div><div class=\"stat-label\">{}</div></div>\
         </div>",
        current_score,
        t!("web.history.current_score"),
        current_findings,
        t!("web.history.current_findings"),
        entries.len(),
        t!("web.history.historical_scans"),
    ));

    // History table
    html.push_str(&format!(
        "<div class=\"card\"><div class=\"card-title\">{}</div>",
        t!("web.history.title")
    ));

    if entries.is_empty() {
        html.push_str(&format!("<p style=\"text-align:center;padding:20px;color:var(--text-secondary);font-size:13px\">{}</p>", t!("web.history.empty")));
    } else {
        html.push_str("<table class=\"findings-table\">");
        html.push_str(&format!(
            "<thead><tr>\
             <th>{}</th><th>{}</th><th>{}</th>\
             <th>{}</th><th>{}</th><th>{}</th><th>{}</th><th>{}</th>\
             </tr></thead><tbody>",
            t!("web.history.table_timestamp"),
            t!("web.history.table_score"),
            t!("web.history.table_findings"),
            t!("web.history.table_sensitive"),
            t!("web.history.table_permissions"),
            t!("web.history.table_exposure"),
            t!("web.history.table_supply_chain"),
            t!("web.history.table_host"),
        ));

        for entry in entries.iter().rev() {
            let ts = html_escape(&entry.timestamp);
            let score_class = if entry.overall >= 80 {
                "var(--success)"
            } else if entry.overall >= 50 {
                "var(--medium)"
            } else {
                "var(--critical)"
            };

            html.push_str(&format!(
                "<tr><td style=\"font-size:12px;color:var(--text-secondary);white-space:nowrap\">{ts}</td>\
                 <td><span style=\"font-weight:600;color:{score_class}\">{}</span></td>\
                 <td>{}</td>", entry.overall, entry.finding_count
            ));

            for axis in Axis::ALL {
                let score = entry.axis_scores.get(&axis).copied().unwrap_or(100);
                let color = if score >= 80 {
                    "var(--success)"
                } else if score >= 50 {
                    "var(--medium)"
                } else {
                    "var(--critical)"
                };
                html.push_str(&format!(
                    "<td style=\"color:{color};font-size:12px\">{score}</td>"
                ));
            }

            html.push_str("</tr>");
        }

        html.push_str("</tbody></table>");
    }

    html.push_str("</div>");

    Html(html)
}
