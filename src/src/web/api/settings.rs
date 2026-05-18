#![cfg(feature = "web")]

use axum::extract::State;
use axum::Json;
use serde::Deserialize;

use crate::settings;
use crate::web::state::AppState;

#[derive(Deserialize)]
pub struct SettingsUpdate {
    pub locale: Option<String>,
    pub theme: Option<String>,
    pub layout: Option<String>,
    pub ui_borders: Option<bool>,
}

pub async fn get_settings(State(state): State<AppState>) -> Json<serde_json::Value> {
    let current = state.settings.read().expect("lock poisoned");
    Json(serde_json::json!({
        "locale": current.locale,
        "theme": current.theme,
        "layout": current.layout,
        "ui_borders": current.ui_borders,
    }))
}

pub async fn update_settings(
    State(state): State<AppState>,
    Json(update): Json<SettingsUpdate>,
) -> Json<serde_json::Value> {
    let mut current = state.settings.write().expect("lock poisoned");

    if let Some(locale) = update.locale
        && !locale.is_empty() && locale != current.locale.as_deref().unwrap_or("")
    {
        current.locale = Some(locale.clone());
        let _ = settings::persist_locale(&locale);
    }
    if let Some(theme) = update.theme
        && !theme.is_empty() && theme != current.theme.as_deref().unwrap_or("")
    {
        current.theme = Some(theme.clone());
        let _ = settings::persist_theme(&theme);
    }
    if let Some(layout) = update.layout
        && !layout.is_empty() && layout != current.layout.as_deref().unwrap_or("")
    {
        current.layout = Some(layout.clone());
        let _ = settings::persist_layout(&layout);
    }
    if let Some(borders) = update.ui_borders
        && borders != current.ui_borders.unwrap_or(true)
    {
        current.ui_borders = Some(borders);
        let _ = settings::persist_ui_borders(borders);
    }

    Json(serde_json::json!({"status": "saved", "settings": &*current}))
}
