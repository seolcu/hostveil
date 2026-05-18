use std::sync::{Arc, RwLock};

use crate::domain::ScanResult;
use crate::settings::AppSettings;

#[derive(Clone)]
pub struct AppState {
    pub scan_result: Arc<RwLock<ScanResult>>,
    pub settings: Arc<RwLock<AppSettings>>,
}

impl AppState {
    pub fn new(scan_result: ScanResult) -> Self {
        let settings = crate::settings::load();
        Self {
            scan_result: Arc::new(RwLock::new(scan_result)),
            settings: Arc::new(RwLock::new(settings)),
        }
    }
}

pub fn error_json(msg: impl std::fmt::Display) -> serde_json::Value {
    serde_json::json!({"status": "error", "error": msg.to_string()})
}
