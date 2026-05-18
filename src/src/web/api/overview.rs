#![cfg(feature = "web")]

use axum::extract::State;
use axum::Json;

use crate::web::state::AppState;

pub async fn overview_json(State(state): State<AppState>) -> Json<serde_json::Value> {
    let scan_result = state.scan_result.read().expect("lock poisoned");

    let total_findings = scan_result.findings.len();

    let severity_counts: serde_json::Map<String, serde_json::Value> = scan_result.score_report.severity_counts
        .iter()
        .map(|(k, v)| (k.as_key().to_owned(), serde_json::json!(v)))
        .collect();

    let axis_scores: serde_json::Map<String, serde_json::Value> = scan_result.score_report.axis_scores
        .iter()
        .map(|(k, v)| (k.as_key().to_owned(), serde_json::json!(v)))
        .collect();

    Json(serde_json::json!({
        "overall_score": scan_result.score_report.overall,
        "total_findings": total_findings,
        "severity_counts": severity_counts,
        "axis_scores": axis_scores,
        "warnings": &scan_result.metadata.warnings,
        "adapters": &scan_result.metadata.adapters,
        "services": &scan_result.metadata.services,
        "scan_mode": scan_result.metadata.scan_mode,
    }))
}
