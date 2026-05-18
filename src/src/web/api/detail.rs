#![cfg(feature = "web")]

use axum::Json;
use axum::extract::{Path, State};

use crate::web::state::{self as web_state, AppState};

pub async fn finding_detail_json(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    let scan_result = match state.scan_result.read() {
        Ok(r) => r,
        Err(_) => return Json(web_state::error_json("Lock poisoned")),
    };
    match scan_result.findings.iter().find(|f| f.id == id) {
        Some(finding) => Json(serde_json::to_value(finding).unwrap_or(serde_json::Value::Null)),
        None => Json(web_state::error_json("Finding not found")),
    }
}
