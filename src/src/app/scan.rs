use crate::compose::ComposeParser;
use crate::domain::ScanResult;
use crate::host::{HostContext, HostScanner};
use crate::rules::RuleEngine;
use crate::scoring;

use super::{AppConfig, AppError};

pub fn run(config: &AppConfig) -> Result<ScanResult, AppError> {
    let mut result = ScanResult::default();
    let mut coverage = scoring::Coverage::default();

    if let Some(path) = &config.compose_path {
        let project = ComposeParser::parse_path(path)?;
        let findings = RuleEngine.scan(&project);

        result.metadata.compose_root = Some(project.working_dir.clone());
        result.metadata.compose_file = Some(project.primary_file.clone());
        result.metadata.loaded_files = project.loaded_files.clone();
        result.metadata.service_count = project.services.len();
        result.findings = findings;
        coverage.compose = true;
    }

    if let Some(host_root) = &config.host_root {
        let findings = HostScanner.scan(&HostContext {
            root: host_root.clone(),
        });

        result.metadata.host_root = Some(host_root.clone());
        result.findings.extend(findings);
        coverage.host_hardening = true;
    }

    result.score_report = scoring::build_score_report_with_coverage(&result.findings, coverage);

    Ok(result)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::run;
    use crate::app::{AppConfig, OutputMode};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn parser_fixture() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../proto/tests/fixtures/parser/docker-compose.yml")
            .canonicalize()
            .expect("parser fixture should exist")
    }

    fn temp_host_root(name: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should move forward")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "hostveil-app-scan-{name}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("temp root should be created");
        path
    }

    fn write_file(path: &std::path::Path, content: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("parent should be created");
        }
        fs::write(path, content).expect("file should be written");
    }

    #[test]
    fn populates_scan_metadata_from_compose_project() {
        let config = AppConfig {
            output_mode: OutputMode::Json,
            show_help: false,
            compose_path: Some(parser_fixture()),
            host_root: None,
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

    #[test]
    fn merges_compose_and_host_findings_into_one_scan_result() {
        let host_root = temp_host_root("combined");
        write_file(
            &host_root.join("etc/ssh/sshd_config"),
            "PermitRootLogin yes\nPasswordAuthentication yes\n",
        );
        write_file(&host_root.join("var/run/docker.sock"), "socket");
        fs::set_permissions(
            host_root.join("var/run/docker.sock"),
            fs::Permissions::from_mode(0o666),
        )
        .expect("permissions should be set");

        let config = AppConfig {
            output_mode: OutputMode::Json,
            show_help: false,
            compose_path: Some(parser_fixture()),
            host_root: Some(host_root.clone()),
        };

        let result = run(&config).expect("combined scan should succeed");

        assert_eq!(result.metadata.service_count, 2);
        assert_eq!(result.metadata.host_root, Some(host_root.clone()));
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.id == "host.ssh_root_login_enabled")
        );
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.id == "host.docker_socket_world_writable")
        );
        assert!(result.score_report.axis_scores[&crate::domain::Axis::HostHardening] < 100);

        fs::remove_dir_all(host_root).expect("temp root should be removed");
    }
}
