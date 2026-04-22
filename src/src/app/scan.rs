use std::env;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver};
use std::thread;

use crate::adapters;
use crate::compose::{ComposeParseError, ComposeParser, ComposeProject};
use crate::discovery::{
    DiscoveredComposeProject, DockerDiscoveryResult, discover_running_compose_projects,
    project_summary,
};
use crate::domain::{
    AdapterStatus, DiscoveredProjectSummary, ScanMode, ScanResult, ServiceSummary,
};
use crate::host::{HostContext, HostScanner, collect_host_runtime_info};
use crate::rules::RuleEngine;
use crate::scoring;

use super::{AppConfig, AppError};

#[derive(Debug)]
pub struct AdapterScanUpdate {
    trivy: adapters::trivy::TrivyScanOutput,
    lynis: adapters::lynis::LynisScanOutput,
    dockle: adapters::dockle::DockleScanOutput,
}

pub fn run(config: &AppConfig) -> Result<ScanResult, AppError> {
    let mut result = run_native(config)?;
    apply_external_adapters(&mut result);
    Ok(result)
}

pub fn run_native(config: &AppConfig) -> Result<ScanResult, AppError> {
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

    result.score_report = scoring::build_score_report_with_coverage(&result.findings, coverage);
    Ok(result)
}

fn apply_external_adapters(result: &mut ScanResult) {
    let update = scan_external_adapters(
        result.metadata.services.clone(),
        result.metadata.host_root.clone(),
    );
    apply_external_adapter_update(result, update);
}

pub fn prepare_background_adapter_scan(result: &mut ScanResult) -> Receiver<AdapterScanUpdate> {
    spawn_background_adapter_scan(result, scan_external_adapters)
}

fn spawn_background_adapter_scan<F>(
    result: &mut ScanResult,
    scan_fn: F,
) -> Receiver<AdapterScanUpdate>
where
    F: FnOnce(Vec<ServiceSummary>, Option<PathBuf>) -> AdapterScanUpdate + Send + 'static,
{
    seed_adapter_statuses(result);

    let services = result.metadata.services.clone();
    let host_root = result.metadata.host_root.clone();
    let (sender, receiver) = mpsc::channel();

    thread::spawn(move || {
        let update = scan_fn(services, host_root);
        let _ = sender.send(update);
    });

    receiver
}

pub fn apply_external_adapter_update(result: &mut ScanResult, update: AdapterScanUpdate) {
    let AdapterScanUpdate {
        trivy,
        lynis,
        dockle,
    } = update;

    result
        .metadata
        .adapters
        .insert(String::from("trivy"), trivy.status);
    result.metadata.warnings.extend(trivy.warnings);
    result.findings.extend(trivy.findings);

    result
        .metadata
        .adapters
        .insert(String::from("lynis"), lynis.status);
    result.metadata.warnings.extend(lynis.warnings);
    result.findings.extend(lynis.findings);

    result
        .metadata
        .adapters
        .insert(String::from("dockle"), dockle.status);
    result.metadata.warnings.extend(dockle.warnings);
    result.findings.extend(dockle.findings);

    result.score_report =
        scoring::build_score_report_with_coverage(&result.findings, coverage_from_result(result));
}

fn scan_external_adapters(
    services: Vec<ServiceSummary>,
    host_root: Option<PathBuf>,
) -> AdapterScanUpdate {
    let trivy_services = services.clone();
    let dockle_services = services;
    let trivy_handle = thread::spawn(move || adapters::trivy::scan(&trivy_services));
    let dockle_handle = thread::spawn(move || adapters::dockle::scan(&dockle_services));
    let lynis_handle = thread::spawn(move || adapters::lynis::scan(host_root.as_deref()));

    AdapterScanUpdate {
        trivy: trivy_handle
            .join()
            .unwrap_or_else(|_| failed_trivy_output()),
        lynis: lynis_handle
            .join()
            .unwrap_or_else(|_| failed_lynis_output()),
        dockle: dockle_handle
            .join()
            .unwrap_or_else(|_| failed_dockle_output()),
    }
}

fn seed_adapter_statuses(result: &mut ScanResult) {
    let trivy_status = if has_image_targets(&result.metadata.services) {
        AdapterStatus::Pending
    } else {
        AdapterStatus::Skipped(t!("adapter.reason.no_image_targets").into_owned())
    };
    result
        .metadata
        .adapters
        .insert(String::from("trivy"), trivy_status);

    let dockle_status = if has_image_targets(&result.metadata.services) {
        AdapterStatus::Pending
    } else {
        AdapterStatus::Skipped(t!("adapter.reason.no_image_targets").into_owned())
    };
    result
        .metadata
        .adapters
        .insert(String::from("dockle"), dockle_status);

    let lynis_status = match result.metadata.host_root.as_deref() {
        None => AdapterStatus::Skipped(t!("adapter.reason.host_not_scanned").into_owned()),
        Some(path) if path != Path::new("/") => {
            AdapterStatus::Skipped(t!("adapter.reason.live_host_only").into_owned())
        }
        Some(_) => AdapterStatus::Pending,
    };
    result
        .metadata
        .adapters
        .insert(String::from("lynis"), lynis_status);
}

fn has_image_targets(services: &[ServiceSummary]) -> bool {
    services.iter().any(|service| {
        service
            .image
            .as_deref()
            .is_some_and(|image| !image.trim().is_empty())
    })
}

fn failed_trivy_output() -> adapters::trivy::TrivyScanOutput {
    adapters::trivy::TrivyScanOutput {
        status: AdapterStatus::Failed(crate::i18n::tr_adapter_scan_thread_panicked("Trivy")),
        findings: Vec::new(),
        warnings: Vec::new(),
    }
}

fn failed_lynis_output() -> adapters::lynis::LynisScanOutput {
    adapters::lynis::LynisScanOutput {
        status: AdapterStatus::Failed(crate::i18n::tr_adapter_scan_thread_panicked("Lynis")),
        findings: Vec::new(),
        warnings: Vec::new(),
    }
}

fn failed_dockle_output() -> adapters::dockle::DockleScanOutput {
    adapters::dockle::DockleScanOutput {
        status: AdapterStatus::Failed(crate::i18n::tr_adapter_scan_thread_panicked("Dockle")),
        findings: Vec::new(),
        warnings: Vec::new(),
    }
}

fn coverage_from_result(result: &ScanResult) -> scoring::Coverage {
    scoring::Coverage {
        compose: result.metadata.compose_file.is_some() || !result.metadata.services.is_empty(),
        host_hardening: result.metadata.host_root.is_some(),
    }
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
    apply_live_discovery_result(&discovery, &env::current_dir()?, result, coverage)
}

fn apply_live_discovery_result(
    discovery: &DockerDiscoveryResult,
    fallback_dir: &Path,
    result: &mut ScanResult,
    coverage: &mut scoring::Coverage,
) -> Result<(), AppError> {
    result.metadata.docker_status = Some(discovery.status.clone());
    result.metadata.warnings.extend(discovery.warnings.clone());

    if !discovery.projects.is_empty() {
        apply_discovered_projects(discovery, result, coverage)?;
        if coverage.compose {
            return Ok(());
        }
    }

    apply_current_dir_fallback_from(fallback_dir, result, coverage)
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

        match load_discovered_project(project) {
            Ok((parsed, warning)) => {
                if let Some(warning) = warning {
                    result.metadata.warnings.push(warning);
                }
                scan_compose_project(&parsed, result);
                coverage.compose = true;
            }
            Err(warning) => {
                result.metadata.warnings.push(warning);
            }
        }
    }

    Ok(())
}

fn load_discovered_project(
    project: &DiscoveredComposeProject,
) -> Result<(ComposeProject, Option<String>), String> {
    if let Some(path) = &project.compose_path {
        match ComposeParser::parse_path(path) {
            Ok(parsed) => return Ok((parsed, None)),
            Err(ComposeParseError::ComposePathMissing { .. })
            | Err(ComposeParseError::ComposeFileNotFound { .. }) => {
                if let Some(working_dir) = project.working_dir.as_ref().filter(|dir| *dir != path) {
                    match ComposeParser::parse_path(working_dir) {
                        Ok(parsed) => {
                            return Ok((
                                parsed,
                                Some(crate::i18n::tr_discovery_recovered_missing_compose_path(
                                    &project.name,
                                    &path.display().to_string(),
                                    &working_dir.display().to_string(),
                                )),
                            ));
                        }
                        Err(ComposeParseError::ComposePathMissing { .. })
                        | Err(ComposeParseError::ComposeFileNotFound { .. }) => {}
                        Err(error) => {
                            return Err(
                                crate::i18n::tr_discovery_missing_compose_path_and_fallback_failed(
                                    &project.name,
                                    &path.display().to_string(),
                                    &working_dir.display().to_string(),
                                    &error.to_string(),
                                ),
                            );
                        }
                    }
                }

                return Err(crate::i18n::tr_discovery_missing_compose_path(
                    &project.name,
                    &path.display().to_string(),
                ));
            }
            Err(error) => {
                return Err(crate::i18n::tr_discovery_parse_failed(
                    &project.name,
                    &error.to_string(),
                ));
            }
        }
    }

    if let Some(working_dir) = &project.working_dir {
        return ComposeParser::parse_path(working_dir)
            .map(|parsed| (parsed, None))
            .map_err(|error| match error {
                ComposeParseError::ComposePathMissing { .. }
                | ComposeParseError::ComposeFileNotFound { .. } => {
                    crate::i18n::tr_discovery_no_compose_file_in_working_dir(
                        &project.name,
                        &working_dir.display().to_string(),
                    )
                }
                _ => crate::i18n::tr_discovery_parse_failed_in_working_dir(
                    &project.name,
                    &working_dir.display().to_string(),
                    &error.to_string(),
                ),
            });
    }

    Err(crate::i18n::tr_discovery_no_usable_compose_path(
        &project.name,
    ))
}

#[cfg(test)]
fn apply_current_dir_fallback(
    result: &mut ScanResult,
    coverage: &mut scoring::Coverage,
) -> Result<(), AppError> {
    let current_dir = env::current_dir()?;
    apply_current_dir_fallback_from(&current_dir, result, coverage)
}

fn apply_current_dir_fallback_from(
    current_dir: &Path,
    result: &mut ScanResult,
    coverage: &mut scoring::Coverage,
) -> Result<(), AppError> {
    match ComposeParser::parse_path(current_dir) {
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
            result
                .metadata
                .warnings
                .push(crate::i18n::tr_discovery_current_dir_fallback_used());
            scan_compose_project(&project, result);
            coverage.compose = true;
            Ok(())
        }
        Err(ComposeParseError::ComposeFileNotFound { .. }) => Ok(()),
        Err(ComposeParseError::ComposePathMissing { .. }) => Ok(()),
        Err(error) => {
            result
                .metadata
                .warnings
                .push(crate::i18n::tr_discovery_current_dir_fallback_failed(
                    &error.to_string(),
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
        result.metadata.services.push(ServiceSummary {
            name: service.name.clone(),
            image: service.image.clone(),
        });
    }

    result.metadata.service_count = result.metadata.services.len();
    result.findings.extend(findings);
}

fn apply_host_scan(host_root: PathBuf, result: &mut ScanResult) {
    let context = HostContext {
        root: host_root.clone(),
    };
    let runtime_info = collect_host_runtime_info(&context);

    result.metadata.host_root = Some(host_root);
    result.metadata.host_runtime = Some(runtime_info.clone());
    result
        .findings
        .extend(HostScanner.scan_with_runtime(&context, &runtime_info));
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::mpsc::TryRecvError;
    use std::thread;
    use std::time::Duration;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::discovery::{DiscoveredComposeProject, DiscoveredContainerService};
    use crate::domain::{
        AdapterStatus, Axis, DockerDiscoveryStatus, Finding, RemediationKind, ScanMode, Scope,
        ServiceSummary, Severity, Source,
    };

    use super::{
        AdapterScanUpdate, apply_current_dir_fallback, apply_current_dir_fallback_from,
        apply_discovered_projects, apply_external_adapter_update, apply_live_discovery_result, run,
        run_native, scan_compose_project, seed_adapter_statuses, spawn_background_adapter_scan,
    };
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

    fn no_image_compose_fixture(name: &str) -> std::path::PathBuf {
        let root = temp_host_root(name);
        let path = root.join("docker-compose.yml");
        write_file(
            &path,
            concat!(
                "services:\n",
                "  web:\n",
                "    build: .\n",
                "    privileged: true\n",
                "    ports:\n",
                "      - \"8080:80\"\n"
            ),
        );
        path
    }

    fn test_finding(
        id: &str,
        axis: Axis,
        severity: Severity,
        scope: Scope,
        source: Source,
        subject: &str,
        related_service: Option<&str>,
    ) -> Finding {
        Finding {
            id: id.to_owned(),
            axis,
            severity,
            scope,
            source,
            subject: subject.to_owned(),
            related_service: related_service.map(str::to_owned),
            title: format!("Synthetic finding {id}"),
            description: format!("Synthetic description for {id}"),
            why_risky: String::from("Synthetic risk explanation"),
            how_to_fix: String::from("Synthetic remediation guidance"),
            evidence: BTreeMap::from([(String::from("id"), id.to_owned())]),
            remediation: RemediationKind::None,
        }
    }

    #[test]
    fn records_trivy_adapter_status_in_scan_metadata() {
        let compose_path = no_image_compose_fixture("trivy-status-no-image");
        let config = AppConfig {
            locale_override: None,
            output_mode: OutputMode::Json,
            show_help: false,
            show_version: false,
            lifecycle_command: None,
            setup_command: None,
            compose_path: Some(compose_path.clone()),
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

        assert!(matches!(status, AdapterStatus::Skipped(_)));

        fs::remove_dir_all(compose_path.parent().expect("fixture dir should exist"))
            .expect("temp dir should be removed");
    }

    #[test]
    fn records_lynis_as_skipped_for_compose_only_scans() {
        let compose_path = no_image_compose_fixture("lynis-compose-only-no-image");
        let config = AppConfig {
            locale_override: None,
            output_mode: OutputMode::Json,
            show_help: false,
            show_version: false,
            lifecycle_command: None,
            setup_command: None,
            compose_path: Some(compose_path.clone()),
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
            .get("lynis")
            .expect("scan should always record Lynis adapter status");

        assert!(matches!(status, AdapterStatus::Skipped(_)));

        fs::remove_dir_all(compose_path.parent().expect("fixture dir should exist"))
            .expect("temp dir should be removed");
    }

    #[test]
    fn records_lynis_as_skipped_for_host_snapshots() {
        let host_root = temp_host_root("lynis-snapshot");
        write_file(&host_root.join("etc/hostname"), "snapshot-host\n");
        write_file(&host_root.join("proc/uptime"), "60.00 0.00\n");
        write_file(
            &host_root.join("proc/loadavg"),
            "0.01 0.01 0.00 1/100 123\n",
        );

        let config = AppConfig {
            locale_override: None,
            output_mode: OutputMode::Json,
            show_help: false,
            show_version: false,
            lifecycle_command: None,
            setup_command: None,
            compose_path: None,
            host_root: Some(host_root.clone()),
            fix_mode: None,
            fix_target_path: None,
            preview_changes: false,
            assume_yes: false,
        };

        let result = run(&config).expect("snapshot host scan should succeed");

        let status = result
            .metadata
            .adapters
            .get("lynis")
            .expect("scan should always record Lynis adapter status");

        assert!(matches!(status, AdapterStatus::Skipped(_)));

        let _ = fs::remove_dir_all(host_root);
    }

    #[test]
    fn populates_scan_metadata_from_compose_project() {
        let config = AppConfig {
            locale_override: None,
            output_mode: OutputMode::Json,
            show_help: false,
            show_version: false,
            lifecycle_command: None,
            setup_command: None,
            compose_path: Some(parser_fixture()),
            host_root: None,
            fix_mode: None,
            fix_target_path: None,
            preview_changes: false,
            assume_yes: false,
        };

        let result = run_native(&config).expect("scan should succeed");

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

        let result =
            run_native(&config).expect("live scan should succeed even without Docker access");

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
        write_file(&host_root.join("var/run/docker.sock"), "socket");
        fs::set_permissions(
            host_root.join("var/run/docker.sock"),
            fs::Permissions::from_mode(0o666),
        )
        .expect("permissions should be set");

        let config = AppConfig {
            locale_override: None,
            output_mode: OutputMode::Json,
            show_help: false,
            show_version: false,
            lifecycle_command: None,
            setup_command: None,
            compose_path: Some(parser_fixture()),
            host_root: Some(host_root.clone()),
            fix_mode: None,
            fix_target_path: None,
            preview_changes: false,
            assume_yes: false,
        };

        let result = run_native(&config).expect("combined scan should succeed");

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
    fn native_and_adapter_findings_share_one_scan_result() {
        let mut result = crate::domain::ScanResult {
            findings: vec![
                test_finding(
                    "project.compose_bundle_loaded",
                    Axis::SensitiveData,
                    Severity::Low,
                    Scope::Project,
                    Source::NativeCompose,
                    "/srv/demo/docker-compose.yml",
                    None,
                ),
                test_finding(
                    "service.public_binding",
                    Axis::UnnecessaryExposure,
                    Severity::Medium,
                    Scope::Service,
                    Source::NativeCompose,
                    "web",
                    Some("web"),
                ),
            ],
            ..Default::default()
        };
        result.metadata.services.push(ServiceSummary {
            name: String::from("web"),
            image: Some(String::from("nginx:1.27.5")),
        });
        result.metadata.host_root = Some(PathBuf::from("/"));

        seed_adapter_statuses(&mut result);
        apply_external_adapter_update(
            &mut result,
            AdapterScanUpdate {
                trivy: crate::adapters::trivy::TrivyScanOutput {
                    status: AdapterStatus::Available,
                    findings: vec![test_finding(
                        "trivy.image_vulnerabilities.nginx_1_27_5",
                        Axis::UpdateSupplyChainRisk,
                        Severity::High,
                        Scope::Image,
                        Source::Trivy,
                        "nginx:1.27.5",
                        Some("web"),
                    )],
                    warnings: Vec::new(),
                },
                lynis: crate::adapters::lynis::LynisScanOutput {
                    status: AdapterStatus::Available,
                    findings: vec![test_finding(
                        "lynis.ssh.password_authentication_enabled",
                        Axis::HostHardening,
                        Severity::High,
                        Scope::Host,
                        Source::Lynis,
                        "/etc/ssh/sshd_config",
                        None,
                    )],
                    warnings: Vec::new(),
                },
                dockle: crate::adapters::dockle::DockleScanOutput {
                    status: AdapterStatus::Available,
                    findings: vec![test_finding(
                        "dockle.image_best_practice.nginx_1_27_5",
                        Axis::UpdateSupplyChainRisk,
                        Severity::Medium,
                        Scope::Image,
                        Source::Dockle,
                        "nginx:1.27.5",
                        Some("web"),
                    )],
                    warnings: Vec::new(),
                },
            },
        );

        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.scope == Scope::Project
                    && finding.source == Source::NativeCompose)
        );
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.scope == Scope::Service
                    && finding.source == Source::NativeCompose)
        );
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.scope == Scope::Image && finding.source == Source::Trivy)
        );
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.scope == Scope::Host && finding.source == Source::Lynis)
        );
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.scope == Scope::Image && finding.source == Source::Dockle)
        );
        assert_eq!(
            result.metadata.adapters.get("trivy"),
            Some(&AdapterStatus::Available)
        );
        assert_eq!(
            result.metadata.adapters.get("lynis"),
            Some(&AdapterStatus::Available)
        );
        assert_eq!(
            result.metadata.adapters.get("dockle"),
            Some(&AdapterStatus::Available)
        );
    }

    #[test]
    fn adapter_status_transitions_and_warnings_are_recorded() {
        let mut result = crate::domain::ScanResult::default();
        result.metadata.host_root = Some(PathBuf::from("/"));
        result.metadata.services.push(ServiceSummary {
            name: String::from("web"),
            image: Some(String::from("nginx:1.27.5")),
        });

        seed_adapter_statuses(&mut result);
        apply_external_adapter_update(
            &mut result,
            AdapterScanUpdate {
                trivy: crate::adapters::trivy::TrivyScanOutput {
                    status: AdapterStatus::Missing,
                    findings: Vec::new(),
                    warnings: vec![String::from("trivy binary missing")],
                },
                lynis: crate::adapters::lynis::LynisScanOutput {
                    status: AdapterStatus::Failed(String::from("lynis crashed")),
                    findings: Vec::new(),
                    warnings: vec![String::from("lynis exited with non-zero status")],
                },
                dockle: crate::adapters::dockle::DockleScanOutput {
                    status: AdapterStatus::Skipped(String::from("no image targets")),
                    findings: Vec::new(),
                    warnings: vec![String::from("dockle intentionally skipped")],
                },
            },
        );

        assert_eq!(
            result.metadata.adapters.get("trivy"),
            Some(&AdapterStatus::Missing)
        );
        assert_eq!(
            result.metadata.adapters.get("lynis"),
            Some(&AdapterStatus::Failed(String::from("lynis crashed")))
        );
        assert_eq!(
            result.metadata.adapters.get("dockle"),
            Some(&AdapterStatus::Skipped(String::from("no image targets")))
        );
        assert!(
            result
                .metadata
                .warnings
                .iter()
                .any(|warning| warning.contains("trivy binary missing"))
        );
        assert!(
            result
                .metadata
                .warnings
                .iter()
                .any(|warning| warning.contains("lynis exited with non-zero status"))
        );
        assert!(
            result
                .metadata
                .warnings
                .iter()
                .any(|warning| warning.contains("dockle intentionally skipped"))
        );
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

    #[test]
    fn service_name_collisions_across_projects_are_preserved() {
        let first =
            ComposeParser::parse_path(parser_fixture()).expect("first project should parse");
        let second_dir = temp_host_root("duplicate-service-name");
        write_file(
            &second_dir.join("docker-compose.yml"),
            concat!(
                "services:\n",
                "  web:\n",
                "    image: caddy:2.9\n",
                "    user: 1000:1000\n"
            ),
        );
        let second = ComposeParser::parse_path(&second_dir).expect("second project should parse");

        let mut result = crate::domain::ScanResult::default();
        scan_compose_project(&first, &mut result);
        scan_compose_project(&second, &mut result);

        assert_eq!(result.metadata.service_count, 3);
        assert_eq!(
            result
                .metadata
                .services
                .iter()
                .filter(|service| service.name == "web")
                .count(),
            2
        );
        assert!(
            result
                .metadata
                .services
                .iter()
                .any(|service| service.name == "web" && service.image.as_deref() == Some("nginx"))
        );
        assert!(
            result
                .metadata
                .services
                .iter()
                .any(|service| service.name == "web"
                    && service.image.as_deref() == Some("caddy:2.9"))
        );

        fs::remove_dir_all(second_dir).expect("temp dir should be removed");
    }

    #[test]
    fn discovered_project_uses_working_dir_when_compose_label_is_stale() {
        let temp_dir = temp_host_root("stale-compose-label");
        write_file(
            &temp_dir.join("docker-compose.yml"),
            concat!("services:\n", "  demo:\n", "    image: nginx:1.27.5\n"),
        );

        let discovery = crate::discovery::DockerDiscoveryResult {
            status: DockerDiscoveryStatus::Available,
            projects: vec![DiscoveredComposeProject {
                name: String::from("demo"),
                compose_path: Some(temp_dir.join("deleted-compose.yml")),
                working_dir: Some(temp_dir.clone()),
                services: vec![DiscoveredContainerService {
                    name: String::from("demo"),
                    image: Some(String::from("nginx:1.27.5")),
                }],
                source: "docker",
            }],
            warnings: Vec::new(),
        };

        let mut result = crate::domain::ScanResult::default();
        let mut coverage = crate::scoring::Coverage::default();

        apply_discovered_projects(&discovery, &mut result, &mut coverage)
            .expect("discovered project should recover from stale label");

        assert!(coverage.compose);
        assert_eq!(result.metadata.service_count, 1);
        assert!(result.metadata.warnings.iter().any(|warning| {
            warning
                == &crate::i18n::tr_discovery_recovered_missing_compose_path(
                    "demo",
                    &temp_dir.join("deleted-compose.yml").display().to_string(),
                    &temp_dir.display().to_string(),
                )
        }));

        fs::remove_dir_all(temp_dir).expect("temp dir should be removed");
    }

    #[test]
    fn discovered_project_reports_stale_docker_metadata_when_paths_are_gone() {
        let missing_root = temp_host_root("missing-compose-label");
        let compose_path = missing_root.join("docker-compose.yml");
        let working_dir = missing_root.join("gone-working-dir");
        fs::remove_dir_all(&missing_root).expect("temp dir should be removed before scan");

        let discovery = crate::discovery::DockerDiscoveryResult {
            status: DockerDiscoveryStatus::Available,
            projects: vec![DiscoveredComposeProject {
                name: String::from("demo"),
                compose_path: Some(compose_path.clone()),
                working_dir: Some(working_dir.clone()),
                services: vec![DiscoveredContainerService {
                    name: String::from("demo"),
                    image: Some(String::from("nginx:1.27.5")),
                }],
                source: "docker",
            }],
            warnings: Vec::new(),
        };

        let mut result = crate::domain::ScanResult::default();
        let mut coverage = crate::scoring::Coverage::default();

        apply_discovered_projects(&discovery, &mut result, &mut coverage)
            .expect("stale discovery warning should not fail the scan");

        assert!(!coverage.compose);
        assert!(result.metadata.warnings.iter().any(|warning| {
            warning
                == &crate::i18n::tr_discovery_missing_compose_path(
                    "demo",
                    &compose_path.display().to_string(),
                )
        }));
    }

    #[test]
    fn live_scan_falls_back_to_current_dir_after_stale_discovery_paths_fail() {
        let missing_root = temp_host_root("live-stale-compose-fallback");
        let current_dir = temp_host_root("live-current-dir-compose");
        let compose_path = missing_root.join("docker-compose.yml");
        let working_dir = missing_root.join("gone-working-dir");
        fs::remove_dir_all(&missing_root).expect("temp dir should be removed before scan");
        write_file(
            &current_dir.join("docker-compose.yml"),
            concat!(
                "services:\n",
                "  demo:\n",
                "    image: nginx:1.27.5\n",
                "    ports:\n",
                "      - \"8080:80\"\n"
            ),
        );

        let discovery = crate::discovery::DockerDiscoveryResult {
            status: DockerDiscoveryStatus::Available,
            projects: vec![DiscoveredComposeProject {
                name: String::from("demo"),
                compose_path: Some(compose_path),
                working_dir: Some(working_dir),
                services: vec![DiscoveredContainerService {
                    name: String::from("demo"),
                    image: Some(String::from("nginx:1.27.5")),
                }],
                source: "docker",
            }],
            warnings: vec![String::from("Docker returned stale Compose labels")],
        };

        let mut result = crate::domain::ScanResult::default();
        let mut coverage = crate::scoring::Coverage {
            host_hardening: true,
            ..Default::default()
        };

        apply_live_discovery_result(&discovery, &current_dir, &mut result, &mut coverage)
            .expect("live scan fallback should succeed");

        assert!(coverage.compose);
        assert_eq!(result.metadata.service_count, 1);
        assert!(
            result
                .metadata
                .warnings
                .iter()
                .any(|warning| warning.contains("stale Compose labels"))
        );
        assert!(
            result.metadata.warnings.iter().any(|warning| {
                warning == &crate::i18n::tr_discovery_current_dir_fallback_used()
            })
        );
        assert_eq!(result.metadata.discovered_projects.len(), 2);
        assert_eq!(result.metadata.discovered_projects[1].source, "current_dir");

        fs::remove_dir_all(current_dir).expect("temp dir should be removed");
    }

    #[test]
    fn background_adapter_scan_does_not_block_tui_startup() {
        let mut result = crate::domain::ScanResult::default();
        result.metadata.host_root = Some(PathBuf::from("/"));
        result.metadata.services.push(ServiceSummary {
            name: String::from("demo"),
            image: Some(String::from("nginx:1.27.5")),
        });

        let receiver = spawn_background_adapter_scan(&mut result, |_, _| {
            thread::sleep(Duration::from_millis(150));
            AdapterScanUpdate {
                trivy: crate::adapters::trivy::TrivyScanOutput {
                    status: AdapterStatus::Missing,
                    findings: Vec::new(),
                    warnings: Vec::new(),
                },
                lynis: crate::adapters::lynis::LynisScanOutput {
                    status: AdapterStatus::Skipped(String::from("not requested")),
                    findings: Vec::new(),
                    warnings: Vec::new(),
                },
                dockle: crate::adapters::dockle::DockleScanOutput {
                    status: AdapterStatus::Missing,
                    findings: Vec::new(),
                    warnings: Vec::new(),
                },
            }
        });

        assert_eq!(
            result.metadata.adapters.get("trivy"),
            Some(&AdapterStatus::Pending)
        );
        assert_eq!(
            result.metadata.adapters.get("dockle"),
            Some(&AdapterStatus::Pending)
        );
        assert_eq!(
            result.metadata.adapters.get("lynis"),
            Some(&AdapterStatus::Pending)
        );
        assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));

        let update = receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("background scan should eventually finish");
        assert_eq!(update.trivy.status, AdapterStatus::Missing);
        assert_eq!(update.dockle.status, AdapterStatus::Missing);
    }

    #[test]
    fn current_dir_fallback_warning_is_localized() {
        let temp_dir = temp_host_root("cwd-fallback-warning");
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

        let mut result = crate::domain::ScanResult::default();
        let mut coverage = crate::scoring::Coverage::default();
        apply_current_dir_fallback_from(&temp_dir, &mut result, &mut coverage)
            .expect("fallback should succeed");

        assert!(
            result.metadata.warnings.iter().any(|warning| {
                warning == &crate::i18n::tr_discovery_current_dir_fallback_used()
            })
        );

        fs::remove_dir_all(temp_dir).expect("temp dir should be removed");
    }

    #[test]
    fn seed_adapter_statuses_marks_pending_for_live_targets() {
        let mut result = crate::domain::ScanResult::default();
        result.metadata.host_root = Some(PathBuf::from("/"));
        result.metadata.services.push(ServiceSummary {
            name: String::from("demo"),
            image: Some(String::from("nginx:1.27.5")),
        });

        seed_adapter_statuses(&mut result);

        assert_eq!(
            result.metadata.adapters.get("lynis"),
            Some(&AdapterStatus::Pending)
        );
        assert_eq!(
            result.metadata.adapters.get("trivy"),
            Some(&AdapterStatus::Pending)
        );
        assert_eq!(
            result.metadata.adapters.get("dockle"),
            Some(&AdapterStatus::Pending)
        );
    }

    #[test]
    fn seed_adapter_statuses_marks_skipped_when_targets_are_missing() {
        let mut result = crate::domain::ScanResult::default();

        seed_adapter_statuses(&mut result);

        assert!(matches!(
            result.metadata.adapters.get("lynis"),
            Some(AdapterStatus::Skipped(_))
        ));
        assert!(matches!(
            result.metadata.adapters.get("trivy"),
            Some(AdapterStatus::Skipped(_))
        ));
        assert!(matches!(
            result.metadata.adapters.get("dockle"),
            Some(AdapterStatus::Skipped(_))
        ));
    }
}
