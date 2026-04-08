use std::env;
use std::path::{Path, PathBuf};

use crate::adapters;
use crate::compose::{ComposeParseError, ComposeParser, ComposeProject};
use crate::discovery::{DockerDiscoveryResult, discover_running_compose_projects, project_summary};
use crate::domain::{DiscoveredProjectSummary, ScanMode, ScanResult, ServiceSummary};
use crate::host::{HostContext, HostScanner, collect_host_runtime_info};
use crate::rules::RuleEngine;
use crate::scoring;

use super::{AppConfig, AppError};

pub fn run(config: &AppConfig) -> Result<ScanResult, AppError> {
    let mut result = ScanResult::default();
    let mut coverage = scoring::Coverage::default();

    if uses_live_discovery(config) {
        run_live_scan(&mut result, &mut coverage)?;
    } else {
        result.metadata.scan_mode = ScanMode::Explicit;

        if let Some(path) = &config.compose_path {
            let project = ComposeParser::parse_path(path)?;
            scan_compose_project(&project, &mut result);
            coverage.compose = true;
        }

        if let Some(host_root) = &config.host_root {
            apply_host_scan(host_root.clone(), &mut result);
            coverage.host_hardening = true;
        }
    }

    apply_external_adapters(&mut result);

    result.score_report = scoring::build_score_report_with_coverage(&result.findings, coverage);
    Ok(result)
}

fn apply_external_adapters(result: &mut ScanResult) {
    let trivy_output = adapters::trivy::scan(&result.metadata.services);
    result
        .metadata
        .adapters
        .insert(String::from("trivy"), trivy_output.status);
    result.metadata.warnings.extend(trivy_output.warnings);
    result.findings.extend(trivy_output.findings);
}

fn uses_live_discovery(config: &AppConfig) -> bool {
    config.compose_path.is_none() && config.host_root.is_none()
}

fn run_live_scan(
    result: &mut ScanResult,
    coverage: &mut scoring::Coverage,
) -> Result<(), AppError> {
    result.metadata.scan_mode = ScanMode::Live;

    let host_root = PathBuf::from("/");
    apply_host_scan(host_root.clone(), result);
    coverage.host_hardening = true;

    let discovery = discover_running_compose_projects();
    result.metadata.docker_status = Some(discovery.status.clone());
    result.metadata.warnings.extend(discovery.warnings.clone());

    if !discovery.projects.is_empty() {
        apply_discovered_projects(&discovery, result, coverage)?;
        if coverage.compose {
            return Ok(());
        }
    }

    apply_current_dir_fallback(result, coverage)
}

fn apply_discovered_projects(
    discovery: &DockerDiscoveryResult,
    result: &mut ScanResult,
    coverage: &mut scoring::Coverage,
) -> Result<(), AppError> {
    for project in &discovery.projects {
        result
            .metadata
            .discovered_projects
            .push(project_summary(project));

        if let Some(path) = &project.compose_path {
            match ComposeParser::parse_path(path) {
                Ok(parsed) => {
                    scan_compose_project(&parsed, result);
                    coverage.compose = true;
                }
                Err(error) => {
                    result.metadata.warnings.push(format!(
                        "Failed to parse discovered project {}: {}",
                        project.name, error
                    ));
                }
            }
        } else {
            result.metadata.warnings.push(format!(
                "Discovered project {} has no usable compose path.",
                project.name
            ));
        }
    }

    Ok(())
}

fn apply_current_dir_fallback(
    result: &mut ScanResult,
    coverage: &mut scoring::Coverage,
) -> Result<(), AppError> {
    let current_dir = env::current_dir()?;

    match ComposeParser::parse_path(&current_dir) {
        Ok(project) => {
            let summary = DiscoveredProjectSummary {
                name: project
                    .primary_file
                    .parent()
                    .and_then(Path::file_name)
                    .and_then(|value| value.to_str())
                    .unwrap_or("current-directory")
                    .to_owned(),
                source: String::from("current_dir"),
                compose_path: Some(project.primary_file.clone()),
                working_dir: Some(project.working_dir.clone()),
                service_count: project.services.len(),
            };
            result.metadata.discovered_projects.push(summary);
            result.metadata.warnings.push(String::from(
                "Using the current directory as a Compose fallback because no running Compose project was discovered.",
            ));
            scan_compose_project(&project, result);
            coverage.compose = true;
            Ok(())
        }
        Err(ComposeParseError::ComposeFileNotFound { .. }) => Ok(()),
        Err(ComposeParseError::ComposePathMissing { .. }) => Ok(()),
        Err(error) => {
            result.metadata.warnings.push(format!(
                "Current-directory Compose fallback failed: {error}"
            ));
            Ok(())
        }
    }
}

fn scan_compose_project(project: &ComposeProject, result: &mut ScanResult) {
    let findings = RuleEngine.scan(project);

    if result.metadata.compose_file.is_none() {
        result.metadata.compose_file = Some(project.primary_file.clone());
    }
    if result.metadata.compose_root.is_none() {
        result.metadata.compose_root = Some(project.working_dir.clone());
    }

    for file in &project.loaded_files {
        if !result.metadata.loaded_files.contains(file) {
            result.metadata.loaded_files.push(file.clone());
        }
    }

    for service in project.services.values() {
        if result
            .metadata
            .services
            .iter()
            .all(|existing| existing.name != service.name)
        {
            result.metadata.services.push(ServiceSummary {
                name: service.name.clone(),
                image: service.image.clone(),
            });
        }
    }

    result.metadata.service_count = result.metadata.services.len();
    result.findings.extend(findings);
}

fn apply_host_scan(host_root: PathBuf, result: &mut ScanResult) {
    let context = HostContext {
        root: host_root.clone(),
    };

    result.metadata.host_root = Some(host_root);
    result.metadata.host_runtime = Some(collect_host_runtime_info(&context));
    result.findings.extend(HostScanner.scan(&context));
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::domain::{AdapterStatus, DockerDiscoveryStatus, ScanMode};

    use super::{apply_current_dir_fallback, run, scan_compose_project};
    use crate::app::{AppConfig, OutputMode};
    use crate::compose::ComposeParser;

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
    fn records_trivy_adapter_status_in_scan_metadata() {
        let config = AppConfig {
            output_mode: OutputMode::Json,
            show_help: false,
            show_version: false,
            compose_path: Some(parser_fixture()),
            host_root: None,
            fix_mode: None,
            fix_target_path: None,
            preview_changes: false,
            assume_yes: false,
        };

        let result = run(&config).expect("scan should succeed");

        let status = result
            .metadata
            .adapters
            .get("trivy")
            .expect("scan should always record Trivy adapter status");

        assert!(matches!(
            status,
            AdapterStatus::Available | AdapterStatus::Missing | AdapterStatus::Failed(_)
        ));
    }

    #[test]
    fn populates_scan_metadata_from_compose_project() {
        let config = AppConfig {
            output_mode: OutputMode::Json,
            show_help: false,
            show_version: false,
            compose_path: Some(parser_fixture()),
            host_root: None,
            fix_mode: None,
            fix_target_path: None,
            preview_changes: false,
            assume_yes: false,
        };

        let result = run(&config).expect("scan should succeed");

        assert_eq!(result.metadata.scan_mode, ScanMode::Explicit);
        assert_eq!(result.metadata.service_count, 2);
        assert_eq!(result.metadata.loaded_files.len(), 2);
        assert!(result.metadata.compose_root.is_some());
        assert!(result.metadata.compose_file.is_some());
        assert_eq!(result.metadata.services.len(), 2);
        assert!(result.metadata.host_runtime.is_none());
        assert!(result.findings.len() >= 4);
        assert_eq!(
            result.score_report.axis_scores[&crate::domain::Axis::ExcessivePermissions],
            10
        );
    }

    #[test]
    fn allows_live_scan_without_explicit_target() {
        let config = AppConfig::default();

        let result = run(&config).expect("live scan should succeed even without Docker access");

        assert_eq!(result.metadata.scan_mode, ScanMode::Live);
        assert!(result.metadata.host_root.is_some());
        assert!(matches!(
            result.metadata.docker_status,
            Some(DockerDiscoveryStatus::Available)
                | Some(DockerDiscoveryStatus::Missing)
                | Some(DockerDiscoveryStatus::PermissionDenied)
                | Some(DockerDiscoveryStatus::Failed(_))
        ));
    }

    #[test]
    fn merges_compose_and_host_findings_into_one_scan_result() {
        let host_root = temp_host_root("combined");
        write_file(
            &host_root.join("etc/ssh/sshd_config"),
            "PermitRootLogin yes\nPasswordAuthentication yes\n",
        );
        write_file(&host_root.join("etc/hostname"), "home-server\n");
        write_file(&host_root.join("proc/uptime"), "1221720.00 0.00\n");
        write_file(
            &host_root.join("proc/loadavg"),
            "0.42 0.31 0.27 1/100 1234\n",
        );
        write_file(
            &host_root.join("etc/fail2ban/jail.local"),
            "[sshd]\nenabled = true\n",
        );
        write_file(
            &host_root.join("etc/systemd/system/multi-user.target.wants/fail2ban.service"),
            "enabled\n",
        );
        write_file(
            &host_root.join("etc/crowdsec/config.yaml"),
            "api:\n  server:\n",
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
            show_version: false,
            compose_path: Some(parser_fixture()),
            host_root: Some(host_root.clone()),
            fix_mode: None,
            fix_target_path: None,
            preview_changes: false,
            assume_yes: false,
        };

        let result = run(&config).expect("combined scan should succeed");

        assert_eq!(result.metadata.service_count, 2);
        assert_eq!(result.metadata.host_root, Some(host_root.clone()));
        assert_eq!(
            result
                .metadata
                .host_runtime
                .as_ref()
                .and_then(|info| info.hostname.as_deref()),
            Some("home-server")
        );
        assert_eq!(
            result
                .metadata
                .host_runtime
                .as_ref()
                .and_then(|info| info.uptime.as_deref()),
            Some("14d 3h 22m")
        );
        assert_eq!(
            result
                .metadata
                .host_runtime
                .as_ref()
                .and_then(|info| info.load_average.as_deref()),
            Some("0.42 0.31 0.27")
        );
        assert_eq!(
            result
                .metadata
                .host_runtime
                .as_ref()
                .map(|info| info.fail2ban),
            Some(crate::domain::DefensiveControlStatus::Enabled)
        );
        assert_eq!(
            result
                .metadata
                .host_runtime
                .as_ref()
                .map(|info| info.crowdsec),
            Some(crate::domain::DefensiveControlStatus::Installed)
        );
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

    #[test]
    fn current_dir_fallback_loads_compose_project_when_docker_finds_nothing() {
        let temp_dir = temp_host_root("cwd-fallback");
        write_file(
            &temp_dir.join("docker-compose.yml"),
            concat!(
                "services:\n",
                "  demo:\n",
                "    image: nginx:1.27.5\n",
                "    ports:\n",
                "      - \"8080:80\"\n"
            ),
        );

        let previous_dir = std::env::current_dir().expect("cwd should be available");
        std::env::set_current_dir(&temp_dir).expect("cwd should change");

        let mut result = crate::domain::ScanResult::default();
        let mut coverage = crate::scoring::Coverage::default();
        apply_current_dir_fallback(&mut result, &mut coverage).expect("fallback should succeed");

        std::env::set_current_dir(previous_dir).expect("cwd should be restored");

        assert!(coverage.compose);
        assert_eq!(result.metadata.service_count, 1);
        assert_eq!(result.metadata.discovered_projects.len(), 1);
        assert_eq!(result.metadata.discovered_projects[0].source, "current_dir");

        fs::remove_dir_all(temp_dir).expect("temp dir should be removed");
    }

    #[test]
    fn compose_projects_can_be_accumulated_from_multiple_sources() {
        let first =
            ComposeParser::parse_path(parser_fixture()).expect("first project should parse");
        let second_dir = temp_host_root("second-compose");
        write_file(
            &second_dir.join("docker-compose.yml"),
            concat!(
                "services:\n",
                "  worker:\n",
                "    image: busybox:1.36\n",
                "    user: 1000:1000\n"
            ),
        );
        let second = ComposeParser::parse_path(&second_dir).expect("second project should parse");

        let mut result = crate::domain::ScanResult::default();
        scan_compose_project(&first, &mut result);
        scan_compose_project(&second, &mut result);

        assert_eq!(result.metadata.service_count, 3);
        assert_eq!(result.metadata.loaded_files.len(), 3);

        fs::remove_dir_all(second_dir).expect("temp dir should be removed");
    }
}
