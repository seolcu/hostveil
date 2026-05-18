#![cfg(feature = "web")]

use axum::extract::{Path, State};
use axum::response::Html;
use rust_i18n::t;

use crate::domain::RemediationKind;
use crate::fix::{self, FixMode};
use crate::web::state::AppState;

use super::overview::html_escape;

pub async fn fix_page(State(state): State<AppState>, Path(id): Path<String>) -> Html<String> {
    let scan_result = state.scan_result.read().expect("lock poisoned");

    let finding = match scan_result.findings.iter().find(|f| f.id == id) {
        Some(f) => f,
        None => {
            return Html(format!(
                "<div style=\"text-align:center;padding:40px;color:var(--text-secondary)\">\
                 <h2>{}</h2>\
                 <p style=\"margin-top:8px\">{}</p>\
                 <a href=\"/findings\" style=\"color:var(--accent)\">{}</a></div>",
                t!("web.fix.not_found"),
                t!("web.findings.not_found_id", id = id),
                t!("web.findings.back_to_findings"),
            ));
        }
    };

    let compose_file = match &scan_result.metadata.compose_file {
        Some(p) => p.clone(),
        None => {
            return Html(format!(
                "<div style=\"text-align:center;padding:40px;color:var(--text-secondary)\">\
                 <h2>{}</h2>\
                 <p style=\"margin-top:8px\">{}</p>\
                 <a href=\"/findings\" style=\"color:var(--accent)\">{}</a></div>",
                t!("web.fix.no_compose"),
                t!("web.fix.no_compose_detail"),
                t!("web.findings.back_to_findings"),
            ));
        }
    };

    let is_fixable = matches!(
        finding.remediation,
        RemediationKind::Auto | RemediationKind::Review
    );

    if !is_fixable {
        let how_esc = html_escape(&finding.how_to_fix);
        let id_esc = html_escape(&finding.id);
        return Html(format!(
            "<div style=\"text-align:center;padding:40px;color:var(--text-secondary)\">\
             <h2>{}</h2>\
             <p style=\"margin-top:8px\">{}</p>\
             <div class=\"card\" style=\"margin-top:20px;text-align:left\"><div class=\"card-title\">{}</div>\
             <p style=\"font-size:13px;line-height:1.6\">{how_esc}</p></div>\
             <a href=\"/findings/{id_esc}\" style=\"color:var(--accent);margin-top:16px;display:inline-block\">{}</a></div>",
            t!("web.fix.manual_title"),
            t!("web.fix.manual_detail"),
            t!("web.findings.how_to_fix"),
            t!("web.findings_detail.back_to_finding"),
            how_esc = how_esc,
            id_esc = id_esc,
        ));
    }

    // Preview the fix
    let plan = match fix::preview(
        &compose_file,
        FixMode::Fix,
        Some(std::slice::from_ref(&finding.id)),
    ) {
        Ok(plan) => plan,
        Err(e) => {
            return Html(format!(
                "<div style=\"text-align:center;padding:40px;color:var(--critical)\">\
                 <h2>{}</h2>\
                 <p style=\"margin-top:8px\">{e}</p>\
                 <a href=\"/findings/{id}\" style=\"color:var(--accent);margin-top:16px;display:inline-block\">{}</a></div>",
                t!("web.fix.preview_failed"),
                t!("web.findings_detail.back_to_finding"),
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
        "<div style=\"margin-bottom:16px\"><a href=\"/findings/{id_esc}\" style=\"color:var(--accent);font-size:13px\">&larr; {}</a></div>",
        t!("web.findings_detail.back_to_finding"),
    ));

    // Title
    html.push_str(&format!(
        "<div class=\"card\" style=\"margin-bottom:20px\">\
         <div style=\"display:flex;justify-content:space-between;align-items:center\">\
         <div><h2 style=\"color:var(--text-bright);font-size:18px;font-weight:600;margin:0\">{title}</h2>\
         <span class=\"severity-badge {sev_class}\" style=\"margin-top:8px;display:inline-block\">{sev}</span></div>\
         <div style=\"font-size:12px;color:var(--text-secondary)\">{}{}</div>\
         </div></div>",
        t!("web.fix.file_label"),
        compose_file.display(),
    ));

    // Plan sections
    if !plan.auto_applied.is_empty() {
        html.push_str(
            "<div class=\"card\" style=\"margin-bottom:16px;border-color:var(--success)\">",
        );
        html.push_str(&format!(
            "<div class=\"card-title\" style=\"color:var(--success)\">{}</div>",
            t!("web.fix.auto_fixes", n = plan.auto_applied.len()),
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
        html.push_str(
            "<div class=\"card\" style=\"margin-bottom:16px;border-color:var(--accent)\">",
        );
        html.push_str(&format!(
            "<div class=\"card-title\" style=\"color:var(--accent)\">{}</div>",
            t!("web.fix.review_changes", n = plan.review_applied.len()),
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
        html.push_str(
            "<div class=\"card\" style=\"margin-bottom:16px;border-color:var(--medium)\">",
        );
        html.push_str(&format!(
            "<div class=\"card-title\" style=\"color:var(--medium)\">{}</div>",
            t!("web.fix.host_edits", n = plan.host_actions.len()),
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
        html.push_str(
            "<div class=\"card\" style=\"margin-bottom:16px;border-color:var(--critical)\">",
        );
        html.push_str(&format!(
            "<div class=\"card-title\" style=\"color:var(--critical)\">{}</div>",
            t!("web.fix.shell_commands", n = plan.system_actions.len()),
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
        html.push_str(
            "<div class=\"card\" style=\"margin-bottom:16px;border-color:var(--text-secondary)\">",
        );
        html.push_str(&format!(
            "<div class=\"card-title\">{}</div>",
            t!("web.fix.compose_edits", n = plan.compose_actions.len()),
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
             <div class=\"card-title\">{}</div>\
             <pre style=\"background:var(--bg-primary);padding:16px;border-radius:6px;font-size:12px;line-height:1.5;overflow-x:auto;color:var(--text-bright)\">{diff_preview}</pre>\
             </div>",
            t!("web.fix.diff_preview"),
        ));
    } else {
        html.push_str(&format!("<div class=\"card\" style=\"margin-bottom:20px;border-color:var(--success)\"><div class=\"card-title\" style=\"color:var(--success)\">{}</div><p style=\"font-size:13px;color:var(--text-secondary)\">{}</p></div>",
            t!("web.fix.no_changes"),
            t!("web.fix.no_changes_detail"),
        ));
    }

    // Action buttons
    if plan.changed() {
        html.push_str(&format!(
            "<div style=\"display:flex;gap:12px;justify-content:flex-end;margin-top:20px\">\
             <a href=\"/findings/{id_esc}\" class=\"btn\" style=\"background:var(--bg-hover);color:var(--text-primary)\">{}</a>\
             <a href=\"#\" class=\"btn btn-primary\" onclick=\"applyFix('{id_esc}')\" id=\"apply-btn\">{}</a>\
             </div>",
            t!("web.fix.cancel"),
            t!("web.fix.apply_fix"),
        ));
    }

    // Apply script
    let applying_text = t!("web.fix.applying");
    let applied_title = t!("web.fix.applied");
    let back_text = t!("web.findings.back_to_findings");
    let failed_title = t!("web.fix.failed");
    let unknown_error_text = t!("web.fix.unknown_error");
    let apply_text = t!("web.fix.apply_fix");

    html.push_str(&format!(
        "<script>\
         function applyFix(id) {{\
           var btn = document.getElementById('apply-btn');\
           btn.textContent = '{applying_text}';\
           btn.style.opacity = '0.6';\
           fetch('/api/fix/apply', {{\
             method: 'POST',\
             headers: {{'Content-Type': 'application/json'}},\
             body: JSON.stringify({{finding_id: id}})\
           }}).then(function(r) {{ return r.json(); }})\
             .then(function(data) {{\
               if (data.status === 'applied') {{\
                 document.getElementById('fix-result').innerHTML = '<div class=\"card\" style=\"border-color:var(--success)\"><div class=\"card-title\" style=\"color:var(--success)\">{applied_title}</div><pre style=\"background:var(--bg-primary);padding:16px;border-radius:6px;font-size:12px;margin-top:8px\">' + data.diff + '</pre><a href=\"/findings\" class=\"btn\" style=\"display:inline-block;margin-top:12px\">{back_text}</a></div>';\
                 btn.style.display = 'none';\
               }} else {{\
                 document.getElementById('fix-result').innerHTML = '<div class=\"card\" style=\"border-color:var(--critical)\"><div class=\"card-title\" style=\"color:var(--critical)\">{failed_title}</div><p style=\"font-size:13px\">' + (data.error || '{unknown_error_text}') + '</p></div>';\
                 btn.textContent = '{apply_text}';\
                 btn.style.opacity = '1';\
               }}\
             }});\
         }}\
         </script>\
         <div id=\"fix-result\"></div>"
    ));

    Html(html)
}
