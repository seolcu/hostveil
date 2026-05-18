#![cfg(feature = "web")]

use std::path::Path;

use axum::extract::State;
use axum::Json;
use serde::Deserialize;

use crate::domain::RemediationKind;
use crate::fix::{self, FixAction, FixMode, FixProposal};
use crate::web::state::AppState;

#[derive(Deserialize)]
pub struct FixRequest {
    finding_id: Option<String>,
    compose_file: Option<String>,
}

fn remediation_key(r: RemediationKind) -> &'static str {
    match r {
        RemediationKind::Auto => "auto",
        RemediationKind::Review => "review",
        RemediationKind::Manual => "manual",
    }
}

fn path_to_str(p: &Path) -> String {
    p.to_string_lossy().to_string()
}

fn proposal_to_json(p: &FixProposal) -> serde_json::Value {
    serde_json::json!({
        "service": p.service,
        "summary": p.summary,
        "remediation": remediation_key(p.remediation),
    })
}

fn action_to_json(a: &FixAction) -> serde_json::Value {
    match a {
        FixAction::ComposeEdit { service, summary, diff } => {
            serde_json::json!({
                "type": "compose_edit",
                "service": service,
                "summary": summary,
                "diff": diff,
            })
        }
        FixAction::HostEdit { path, summary, original_content, updated_content, mode } => {
            serde_json::json!({
                "type": "host_edit",
                "path": path_to_str(path),
                "summary": summary,
                "original_content": original_content,
                "updated_content": updated_content,
                "mode": mode,
            })
        }
        FixAction::ShellCommand { command, summary, rollback } => {
            serde_json::json!({
                "type": "shell_command",
                "command": command,
                "summary": summary,
                "rollback": rollback,
            })
        }
    }
}

fn proposals_to_json(proposals: &[FixProposal]) -> Vec<serde_json::Value> {
    proposals.iter().map(proposal_to_json).collect()
}

fn actions_to_json(actions: &[FixAction]) -> Vec<serde_json::Value> {
    actions.iter().map(action_to_json).collect()
}

fn get_compose_file(state: &AppState, req: &FixRequest) -> Option<String> {
    if let Some(ref path) = req.compose_file {
        return Some(path.clone());
    }
    let scan_result = state.scan_result.read().expect("lock poisoned");
    scan_result.metadata.compose_file.as_ref().map(|p| path_to_str(p))
}

pub async fn fix_preview(
    State(state): State<AppState>,
    Json(req): Json<FixRequest>,
) -> Json<serde_json::Value> {
    let compose_file = match get_compose_file(&state, &req) {
        Some(p) => p,
        None => return Json(serde_json::json!({"error": "No compose file available"})),
    };

    let only = req.finding_id.as_ref().map(|id| vec![id.clone()]);
    let only_slice = only.as_deref();

    match fix::preview(&compose_file, FixMode::Fix, only_slice) {
        Ok(plan) => Json(serde_json::json!({
            "compose_file": path_to_str(&plan.compose_file),
            "diff_preview": plan.diff_preview,
            "auto_applied": proposals_to_json(&plan.auto_applied),
            "review_applied": proposals_to_json(&plan.review_applied),
            "host_actions": actions_to_json(&plan.host_actions),
            "system_actions": actions_to_json(&plan.system_actions),
            "compose_actions": actions_to_json(&plan.compose_actions),
            "changed": plan.changed(),
        })),
        Err(e) => Json(serde_json::json!({"error": e.to_string()})),
    }
}

pub async fn fix_apply(
    State(state): State<AppState>,
    Json(req): Json<FixRequest>,
) -> Json<serde_json::Value> {
    let compose_file = match get_compose_file(&state, &req) {
        Some(p) => p,
        None => return Json(serde_json::json!({"error": "No compose file available"})),
    };

    let only = req.finding_id.as_ref().map(|id| vec![id.clone()]);
    let only_slice = only.as_deref();

    match fix::apply(&compose_file, FixMode::Fix, only_slice) {
        Ok(plan) => Json(serde_json::json!({
            "status": "applied",
            "diff": plan.diff_preview,
            "auto_applied": plan.auto_applied.len(),
            "review_applied": plan.review_applied.len(),
        })),
        Err(e) => Json(serde_json::json!({"status": "error", "error": e.to_string()})),
    }
}
