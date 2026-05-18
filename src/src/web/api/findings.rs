#![cfg(feature = "web")]

use axum::Json;
use axum::extract::{Query, State};
use serde::Deserialize;

use crate::domain::{Finding, Scope, Severity, Source};
use crate::web::state::AppState;

#[derive(Debug, Deserialize)]
pub struct FindingsQuery {
    severity: Option<String>,
    source: Option<String>,
    scope: Option<String>,
    service: Option<String>,
    search: Option<String>,
    sort: Option<String>,
    limit: Option<usize>,
}

fn parse_source(s: &str) -> Option<Source> {
    match s {
        "native_compose" => Some(Source::NativeCompose),
        "native_host" => Some(Source::NativeHost),
        "trivy" => Some(Source::Trivy),
        "lynis" => Some(Source::Lynis),
        "dockle" => Some(Source::Dockle),
        "gitleaks" => Some(Source::Gitleaks),
        _ => None,
    }
}

fn parse_scope(s: &str) -> Option<Scope> {
    match s {
        "service" => Some(Scope::Service),
        "image" => Some(Scope::Image),
        "host" => Some(Scope::Host),
        "project" => Some(Scope::Project),
        _ => None,
    }
}

pub async fn findings_json(
    State(state): State<AppState>,
    Query(query): Query<FindingsQuery>,
) -> Json<serde_json::Value> {
    let scan_result = state.scan_result.read().expect("lock poisoned");

    let severity_filter = query.severity.as_deref().and_then(Severity::from_key);
    let source_filter = query.source.as_deref().and_then(parse_source);
    let scope_filter = query.scope.as_deref().and_then(parse_scope);
    let search = query.search.as_deref().unwrap_or("").to_lowercase();
    let limit = query.limit.unwrap_or(usize::MAX);

    let mut findings: Vec<&Finding> = scan_result.findings.iter().collect();

    findings.retain(|f| {
        severity_filter.is_none_or(|s| f.severity == s)
            && source_filter.is_none_or(|s| f.source == s)
            && scope_filter.is_none_or(|s| f.scope == s)
            && query
                .service
                .as_deref()
                .is_none_or(|svc| f.related_service.as_deref() == Some(svc))
            && (search.is_empty()
                || f.title.to_lowercase().contains(&search)
                || f.description.to_lowercase().contains(&search)
                || f.subject.to_lowercase().contains(&search))
    });

    if let Some(sort) = &query.sort {
        match sort.as_str() {
            "severity" => findings.sort_by_key(|a| a.severity),
            "source" => findings.sort_by(|a, b| a.source.as_key().cmp(b.source.as_key())),
            "subject" => findings.sort_by(|a, b| a.subject.cmp(&b.subject)),
            _ => {}
        }
    }

    findings.truncate(limit);

    let services: Vec<String> = {
        let mut svcs: Vec<String> = scan_result
            .findings
            .iter()
            .filter_map(|f| f.related_service.clone())
            .collect();
        svcs.sort();
        svcs.dedup();
        svcs
    };

    Json(serde_json::json!({
        "total": scan_result.findings.len(),
        "filtered": findings.len(),
        "findings": findings,
        "services": services,
    }))
}
