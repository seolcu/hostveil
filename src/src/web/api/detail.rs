#![cfg(feature = "web")]

use axum::extract::{Path, State};
use axum::Json;

use crate::web::state::AppState;

pub async fn finding_detail_json(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    let scan_result = state.scan_result.read().expect("lock poisoned");
    let finding = scan_result.findings.iter().find(|f| f.id == id);
    Json(serde_json::to_value(finding).unwrap_or_default())
}
