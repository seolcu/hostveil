use std::net::SocketAddr;

use axum::extract::State;
use axum::response::Html;
use axum::routing::{get, post};
use axum::Router;

use super::api;
use super::pages;
use super::state::AppState;

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index_html))
        .route("/dashboard", get(pages::overview::overview_page))
        .route("/findings", get(pages::findings::findings_page))
        .route("/findings/{id}", get(pages::findings::finding_detail))
        .route("/history", get(pages::history::history_page))
        .route("/fix/{id}", get(pages::fix::fix_page))
        .route("/api/overview", get(api::overview::overview_json))
        .route("/api/findings", get(api::findings::findings_json))
        .route("/api/findings/{id}", get(api::detail::finding_detail_json))
        .route("/api/fix/preview", post(api::fix::fix_preview))
        .route("/api/fix/apply", post(api::fix::fix_apply))
        .route("/api/rescan", post(api::scan::rescan))
        .route("/api/history", get(api::history::history_json))
        .route("/api/settings", get(api::settings::get_settings))
        .route("/api/settings", post(api::settings::update_settings))
        .with_state(state)
}

async fn index_html(State(state): State<AppState>) -> Html<String> {
    let mut template = include_str!("index.html").to_string();
    let content = pages::overview::overview_page(State(state)).await;
    template = template.replace(
        "<div id=\"content-placeholder\"></div>",
        &content.0,
    );
    Html(template)
}

pub async fn run_server(state: AppState, host: &str, port: u16) -> Result<(), String> {
    let addr: SocketAddr = format!("{host}:{port}")
        .parse()
        .map_err(|e| format!("Invalid address: {e}"))?;

    let router = build_router(state);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("Failed to bind: {e}"))?;

    eprintln!("Hostveil web interface running on http://{addr}/");
    eprintln!("Press Ctrl+C to stop.");

    axum::serve(listener, router)
        .await
        .map_err(|e| format!("Server error: {e}"))?;

    Ok(())
}
