#![cfg(feature = "web")]

use axum::extract::{Path, State};
use axum::response::Html;

use crate::domain::RemediationKind;
use crate::fix::{self, FixMode};
use crate::web::state::AppState;

use super::overview::html_escape;

pub async fn fix_page(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Html<String> {
    let scan_result = state.scan_result.read().expect("lock poisoned");

    let finding = match scan_result.findings.iter().find(|f| f.id == id) {
        Some(f) => f,
        None => {
            return Html(format!(
                "<div style=\"text-align:center;padding:40px;color:var(--text-secondary)\">\
                 <h2>Finding Not Found</h2>\
                 <p style=\"margin-top:8px\">No finding with ID: {id}</p>\
                 <a href=\"/findings\" style=\"color:var(--accent)\">Back to findings</a></div>"
            ));
        }
    };

    let compose_file = match &scan_result.metadata.compose_file {
        Some(p) => p.clone(),
        None => {
            return Html(
                "<div style=\"text-align:center;padding:40px;color:var(--text-secondary)\">\
                 <h2>No Compose File</h2>\
                 <p style=\"margin-top:8px\">Fix is only available for compose-based scans.</p>\
                 <a href=\"/findings\" style=\"color:var(--accent)\">Back to findings</a></div>".to_owned()
            );
        }
    };

    let is_fixable = matches!(
        finding.remediation,
        RemediationKind::Auto | RemediationKind::Review
    );

    if !is_fixable {
        return Html(format!(
            "<div style=\"text-align:center;padding:40px;color:var(--text-secondary)\">\
             <h2>Manual Fix Required</h2>\
             <p style=\"margin-top:8px\">This finding requires manual remediation and cannot be auto-fixed.</p>\
             <div class=\"card\" style=\"margin-top:20px;text-align:left\"><div class=\"card-title\">How to Fix</div>\
             <p style=\"font-size:13px;line-height:1.6\">{how}</p></div>\
             <a href=\"/findings/{id}\" style=\"color:var(--accent);margin-top:16px;display:inline-block\">Back to finding</a></div>",
            id = html_escape(&finding.id),
            how = html_escape(&finding.how_to_fix),
        ));
    }

    // Preview the fix
    let plan = match fix::preview(&compose_file, FixMode::Fix, Some(std::slice::from_ref(&finding.id))) {
        Ok(plan) => plan,
        Err(e) => {
            return Html(format!(
                "<div style=\"text-align:center;padding:40px;color:var(--critical)\">\
                 <h2>Fix Preview Failed</h2>\
                 <p style=\"margin-top:8px\">{e}</p>\
                 <a href=\"/findings/{id}\" style=\"color:var(--accent);margin-top:16px;display:inline-block\">Back to finding</a></div>",
                id = html_escape(&finding.id),
            ));
        }
    };

    let title = html_escape(&finding.title);
    let sev = finding.severity.as_key();
    let id_esc = html_escape(&finding.id);
    let sev_class = finding.severity.as_key();
    let diff_preview = html_escape(&plan.diff_preview);

    let mut html = String::new();

    // Back link
    html.push_str(&format!(
        "<div style=\"margin-bottom:16px\"><a href=\"/findings/{id_esc}\" style=\"color:var(--accent);font-size:13px\">&larr; Back to finding</a></div>"
    ));

    // Title
    html.push_str(&format!(
        "<div class=\"card\" style=\"margin-bottom:20px\">\
         <div style=\"display:flex;justify-content:space-between;align-items:center\">\
         <div><h2 style=\"color:var(--text-bright);font-size:18px;font-weight:600;margin:0\">{title}</h2>\
         <span class=\"severity-badge {sev_class}\" style=\"margin-top:8px;display:inline-block\">{sev}</span></div>\
         <div style=\"font-size:12px;color:var(--text-secondary)\">File: {file}</div>\
         </div></div>",
        file = compose_file.display(),
    ));

    // Plan sections
    if !plan.auto_applied.is_empty() {
        html.push_str("<div class=\"card\" style=\"margin-bottom:16px;border-color:var(--success)\">");
        html.push_str(&format!(
            "<div class=\"card-title\" style=\"color:var(--success)\">Auto Fixes ({n})</div>",
            n = plan.auto_applied.len()
        ));
        for proposal in &plan.auto_applied {
            let s = html_escape(&proposal.summary);
            let svc = html_escape(&proposal.service);
            html.push_str(&format!(
                "<div style=\"padding:6px 0;font-size:13px\"><strong>{svc}:</strong> {s}</div>"
            ));
        }
        html.push_str("</div>");
    }

    if !plan.review_applied.is_empty() {
        html.push_str("<div class=\"card\" style=\"margin-bottom:16px;border-color:var(--accent)\">");
        html.push_str(&format!(
            "<div class=\"card-title\" style=\"color:var(--accent)\">Review Changes ({n})</div>",
            n = plan.review_applied.len()
        ));
        for proposal in &plan.review_applied {
            let s = html_escape(&proposal.summary);
            let svc = html_escape(&proposal.service);
            html.push_str(&format!(
                "<div style=\"padding:6px 0;font-size:13px\"><strong>{svc}:</strong> {s}</div>"
            ));
        }
        html.push_str("</div>");
    }

    // Host actions
    if !plan.host_actions.is_empty() {
        html.push_str("<div class=\"card\" style=\"margin-bottom:16px;border-color:var(--medium)\">");
        html.push_str(&format!(
            "<div class=\"card-title\" style=\"color:var(--medium)\">Host Edits ({n})</div>",
            n = plan.host_actions.len()
        ));
        for action in &plan.host_actions {
            let s = html_escape(action.summary());
            html.push_str(&format!(
                "<div style=\"padding:6px 0;font-size:13px\">{s}</div>"
            ));
        }
        html.push_str("</div>");
    }

    // Shell actions
    if !plan.system_actions.is_empty() {
        html.push_str("<div class=\"card\" style=\"margin-bottom:16px;border-color:var(--critical)\">");
        html.push_str(&format!(
            "<div class=\"card-title\" style=\"color:var(--critical)\">Shell Commands ({n})</div>",
            n = plan.system_actions.len()
        ));
        for action in &plan.system_actions {
            let s = html_escape(action.summary());
            html.push_str(&format!(
                "<div style=\"padding:6px 0;font-size:13px\">{s}</div>"
            ));
        }
        html.push_str("</div>");
    }

    // Compose actions
    if !plan.compose_actions.is_empty() {
        html.push_str("<div class=\"card\" style=\"margin-bottom:16px;border-color:var(--text-secondary)\">");
        html.push_str(&format!(
            "<div class=\"card-title\">Compose File Edits ({n})</div>",
            n = plan.compose_actions.len()
        ));
        for action in &plan.compose_actions {
            let s = html_escape(action.summary());
            html.push_str(&format!(
                "<div style=\"padding:6px 0;font-size:13px\">{s}</div>"
            ));
        }
        html.push_str("</div>");
    }

    // Diff preview
    if plan.changed() {
        html.push_str(&format!(
            "<div class=\"card\" style=\"margin-bottom:20px\">\
             <div class=\"card-title\">Diff Preview</div>\
             <pre style=\"background:var(--bg-primary);padding:16px;border-radius:6px;font-size:12px;line-height:1.5;overflow-x:auto;color:var(--text-bright)\">{diff_preview}</pre>\
             </div>"
        ));
    } else {
        html.push_str("<div class=\"card\" style=\"margin-bottom:20px;border-color:var(--success)\"><div class=\"card-title\" style=\"color:var(--success)\">No Changes Needed</div><p style=\"font-size:13px;color:var(--text-secondary)\">The compose file is already in a good state.</p></div>");
    }

    // Action buttons
    if plan.changed() {
        html.push_str(&format!(
            "<div style=\"display:flex;gap:12px;justify-content:flex-end;margin-top:20px\">\
             <a href=\"/findings/{id_esc}\" class=\"btn\" style=\"background:var(--bg-hover);color:var(--text-primary)\">Cancel</a>\
             <a href=\"#\" class=\"btn btn-primary\" onclick=\"applyFix('{id_esc}')\" id=\"apply-btn\">Apply Fix</a>\
             </div>"
        ));
    }

    // Apply script
    html.push_str(
        "<script>\
         function applyFix(id) {\
           var btn = document.getElementById('apply-btn');\
           btn.textContent = 'Applying...';\
           btn.style.opacity = '0.6';\
           fetch('/api/fix/apply', {\
             method: 'POST',\
             headers: {'Content-Type': 'application/json'},\
             body: JSON.stringify({finding_id: id})\
           }).then(function(r) { return r.json(); })\
             .then(function(data) {\
               if (data.status === 'applied') {\
                 document.getElementById('fix-result').innerHTML = '<div class=\"card\" style=\"border-color:var(--success)\"><div class=\"card-title\" style=\"color:var(--success)\">Fix Applied Successfully</div><pre style=\"background:var(--bg-primary);padding:16px;border-radius:6px;font-size:12px;margin-top:8px\">' + data.diff + '</pre><a href=\"/findings\" class=\"btn\" style=\"display:inline-block;margin-top:12px\">Back to Findings</a></div>';\
                 btn.style.display = 'none';\
               } else {\
                 document.getElementById('fix-result').innerHTML = '<div class=\"card\" style=\"border-color:var(--critical)\"><div class=\"card-title\" style=\"color:var(--critical)\">Fix Failed</div><p style=\"font-size:13px\">' + (data.error || 'Unknown error') + '</p></div>';\
                 btn.textContent = 'Apply Fix';\
                 btn.style.opacity = '1';\
               }\
             });\
         }\
         </script>\
         <div id=\"fix-result\"></div>"
    );

    Html(html)
}
