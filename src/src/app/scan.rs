use crate::compose::ComposeParser;
use crate::domain::ScanResult;
use crate::rules::RuleEngine;
use crate::scoring;

use super::{AppConfig, AppError};

pub fn run(config: &AppConfig) -> Result<ScanResult, AppError> {
    let mut result = ScanResult::default();

    if let Some(path) = &config.compose_path {
        let project = ComposeParser::parse_path(path)?;
        let findings = RuleEngine.scan(&project);

        result.metadata.compose_root = Some(project.working_dir.clone());
        result.metadata.compose_file = Some(project.primary_file.clone());
        result.metadata.loaded_files = project.loaded_files.clone();
        result.metadata.service_count = project.services.len();
        result.score_report = scoring::build_score_report(&findings);
        result.findings = findings;
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::run;
    use crate::app::{AppConfig, OutputMode};

    fn parser_fixture() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../proto/tests/fixtures/parser/docker-compose.yml")
            .canonicalize()
            .expect("parser fixture should exist")
    }

    #[test]
    fn populates_scan_metadata_from_compose_project() {
        let config = AppConfig {
            output_mode: OutputMode::Json,
            show_help: false,
            compose_path: Some(parser_fixture()),
        };

        let result = run(&config).expect("scan should succeed");

        assert_eq!(result.metadata.service_count, 2);
        assert_eq!(result.metadata.loaded_files.len(), 2);
        assert!(result.metadata.compose_root.is_some());
        assert!(result.metadata.compose_file.is_some());
        assert_eq!(result.findings.len(), 4);
        assert_eq!(
            result.score_report.axis_scores[&crate::domain::Axis::ExcessivePermissions],
            10
        );
    }

    #[test]
    fn allows_bootstrap_without_scan_target() {
        let config = AppConfig::default();

        let result = run(&config).expect("bootstrap without target should succeed");

        assert_eq!(result.metadata.service_count, 0);
        assert!(result.metadata.compose_file.is_none());
    }
}
