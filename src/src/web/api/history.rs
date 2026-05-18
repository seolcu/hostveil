#![cfg(feature = "web")]

use axum::extract::State;
use axum::Json;

use crate::history;
use crate::web::state::AppState;

pub async fn history_json(State(state): State<AppState>) -> Json<serde_json::Value> {
    let scan_result = state.scan_result.read().expect("lock poisoned");

    let scan_history = history::load();
    let entries = scan_history.trend(50);

    Json(serde_json::json!({
        "current_score": scan_result.score_report.overall,
        "current_findings": scan_result.findings.len(),
        "entries": entries,
    }))
}
