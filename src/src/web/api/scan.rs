#![cfg(feature = "web")]

use axum::Json;
use axum::extract::State;

use crate::app::{self, AdapterSelection, AppConfig, OutputMode};
use crate::web::state::AppState;

pub async fn rescan(State(state): State<AppState>) -> Json<serde_json::Value> {
    let config = {
        let scan_result = state.scan_result.read().expect("lock poisoned");
        let compose_path = scan_result.metadata.compose_file.clone();
        let host_root = scan_result.metadata.host_root.clone();

        let mut config = AppConfig {
            output_mode: OutputMode::Json,
            adapter_selection: AdapterSelection::all(),
            ..AppConfig::default()
        };
        config.compose_path = compose_path;
        config.host_root = host_root;
        config
    };

    match app::scan::run(&config) {
        Ok(new_result) => {
            let mut scan_result = state.scan_result.write().expect("lock poisoned");
            *scan_result = new_result;

            Json(serde_json::json!({
                "status": "ok",
                "overall": scan_result.score_report.overall,
                "total_findings": scan_result.findings.len(),
            }))
        }
        Err(e) => Json(serde_json::json!({"status": "error", "error": e.to_string()})),
    }
}
