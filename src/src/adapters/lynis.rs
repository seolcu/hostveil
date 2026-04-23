use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::adapters::command;
use crate::domain::{AdapterStatus, Axis, Finding, RemediationKind, Scope, Severity, Source};

const LIVE_HOST_ROOT: &str = "/";
const LYNIS_PID_EXISTS_MESSAGE: &str = "PID file exists, probably another Lynis process is running";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LynisScanOutput {
    pub status: AdapterStatus,
    pub findings: Vec<Finding>,
    pub warnings: Vec<String>,
}

pub fn scan(host_root: Option<&Path>) -> LynisScanOutput {
    scan_with_effective_root(host_root, is_effective_root())
}

fn scan_with_effective_root(host_root: Option<&Path>, effective_root: bool) -> LynisScanOutput {
    let mut output = LynisScanOutput {
        status: AdapterStatus::Skipped(t!("adapter.reason.host_not_scanned").into_owned()),
        findings: Vec::new(),
        warnings: Vec::new(),
    };

    let Some(host_root) = host_root else {
        return output;
    };

    if host_root != Path::new(LIVE_HOST_ROOT) {
        output.status = AdapterStatus::Skipped(t!("adapter.reason.live_host_only").into_owned());
        return output;
    }

    if !effective_root {
        output.status =
            AdapterStatus::Skipped(t!("app.adapter.lynis_root_required_skipped").into_owned());
        return output;
    }

    match detect_lynis() {
        LynisAvailability::Missing => {
            output.status = AdapterStatus::Missing;
            return output;
        }
        LynisAvailability::Available => {
            output.status = AdapterStatus::Available;
        }
        LynisAvailability::Failed(detail) => {
            output.status = AdapterStatus::Failed(detail);
            return output;
        }
    }

    let temp_files = temp_report_files();
    let command_result = run_lynis(&temp_files);
    let report_text = fs::read_to_string(&temp_files.report_file);
    cleanup_temp_files(&temp_files);

    let report_text = match report_text {
        Ok(report_text) => report_text,
        Err(_) => {
            output.status = match command_result {
                Ok(command_result) if !command_result.success => AdapterStatus::Failed(
                    command_result
                        .detail
                        .unwrap_or_else(|| t!("app.adapter.lynis_report_missing").into_owned()),
                ),
                Ok(_) => AdapterStatus::Failed(t!("app.adapter.lynis_report_missing").into_owned()),
                Err(error) => AdapterStatus::Failed(error),
            };
            return output;
        }
    };

    let report = match parse_report(&report_text) {
        Ok(report) => report,
        Err(error) => {
            output.status = AdapterStatus::Failed(error);
            return output;
        }
    };

    match command_result {
        Ok(command_result) => {
            if !command_result.success {
                let detail = command_result
                    .detail
                    .unwrap_or_else(|| t!("app.server.not_available").into_owned());
                output.warnings.push(
                    t!("app.adapter.lynis_non_zero_exit", detail = detail.as_str()).into_owned(),
                );
            }
        }
        Err(error) => {
            output.status = AdapterStatus::Failed(error);
            return output;
        }
    }

    output.findings = report_to_findings(&report, host_root, LynisMode::Full);
    output
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LynisMode {
    Full,
}

impl LynisMode {
    fn as_evidence_value(self) -> &'static str {
        match self {
            Self::Full => "full",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LynisAvailability {
    Available,
    Missing,
    Failed(String),
}

fn detect_lynis() -> LynisAvailability {
    detect_lynis_with_command("lynis")
}

fn detect_lynis_with_command(command_name: &str) -> LynisAvailability {
    detect_lynis_with_command_and_timeout(command_name, command::DEFAULT_ADAPTER_TIMEOUT)
}

fn detect_lynis_with_command_and_timeout(
    command_name: &str,
    timeout: Duration,
) -> LynisAvailability {
    let mut command = Command::new(command_name);
    command.arg("--version").env("NO_COLOR", "1");
    let output = command::run_with_timeout(command, timeout);

    match output {
        Ok(output) if output.status.success() => LynisAvailability::Available,
        Ok(output) => LynisAvailability::Failed(command_detail(&output.stderr, &output.stdout)),
        Err(error) if error.is_not_found() => LynisAvailability::Missing,
        Err(error) => LynisAvailability::Failed(error.detail()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LynisTempFiles {
    report_file: PathBuf,
    log_file: PathBuf,
}

fn temp_report_files() -> LynisTempFiles {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should move forward")
        .as_nanos();
    let prefix = format!("hostveil-lynis-{}-{nanos}", std::process::id());

    LynisTempFiles {
        report_file: env::temp_dir().join(format!("{prefix}.report.dat")),
        log_file: env::temp_dir().join(format!("{prefix}.log")),
    }
}

fn cleanup_temp_files(files: &LynisTempFiles) {
    let _ = fs::remove_file(&files.report_file);
    let _ = fs::remove_file(&files.log_file);
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LynisCommandResult {
    success: bool,
    detail: Option<String>,
}

fn run_lynis(files: &LynisTempFiles) -> Result<LynisCommandResult, String> {
    run_lynis_with_command("lynis", files, command::DEFAULT_ADAPTER_TIMEOUT)
}

fn build_lynis_command(command_name: &str, files: &LynisTempFiles) -> Command {
    let mut command = Command::new(command_name);
    command
        .args(["audit", "system", "--cronjob", "--quiet", "--nocolors"])
        .arg("--report-file")
        .arg(&files.report_file)
        .arg("--logfile")
        .arg(&files.log_file)
        .env("NO_COLOR", "1");
    command
}

fn run_lynis_with_command(
    command_name: &str,
    files: &LynisTempFiles,
    timeout: Duration,
) -> Result<LynisCommandResult, String> {
    let output = command::run_with_timeout(build_lynis_command(command_name, files), timeout)
        .map_err(|error| error.detail())?;
    let detail = command_detail(&output.stderr, &output.stdout);

    if !output.status.success() && is_pid_lockout_detail(&detail) {
        let pid_paths = known_lynis_pid_files();
        let cleanup = cleanup_stale_pid_files(&pid_paths, inspect_process_kind);

        if cleanup.active_lynis {
            return Err(t!("app.adapter.lynis_running_elsewhere").into_owned());
        }

        if cleanup.removed_any {
            let retry_output =
                command::run_with_timeout(build_lynis_command(command_name, files), timeout)
                    .map_err(|error| error.detail())?;
            let retry_detail = command_detail(&retry_output.stderr, &retry_output.stdout);

            return Ok(LynisCommandResult {
                success: retry_output.status.success(),
                detail: Some(retry_detail),
            });
        }
    }

    Ok(LynisCommandResult {
        success: output.status.success(),
        detail: Some(detail),
    })
}

fn is_pid_lockout_detail(detail: &str) -> bool {
    detail.contains(LYNIS_PID_EXISTS_MESSAGE)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcessKind {
    Missing,
    Lynis,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct PidCleanupOutcome {
    removed_any: bool,
    active_lynis: bool,
}

fn known_lynis_pid_files() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Some(home) = env::var_os("HOME").filter(|value| !value.is_empty()) {
        paths.push(PathBuf::from(home).join("lynis.pid"));
    }

    if let Ok(current_dir) = env::current_dir() {
        paths.push(current_dir.join("lynis.pid"));
    }

    paths.push(PathBuf::from("/var/run/lynis.pid"));
    paths
}

fn cleanup_stale_pid_files<F>(paths: &[PathBuf], inspect_process: F) -> PidCleanupOutcome
where
    F: Fn(u32) -> ProcessKind,
{
    let mut outcome = PidCleanupOutcome::default();

    for path in paths {
        let Ok(contents) = fs::read_to_string(path) else {
            continue;
        };

        let pid = contents.trim().parse::<u32>().ok();
        let should_remove = match pid {
            None => true,
            Some(pid) => match inspect_process(pid) {
                ProcessKind::Missing | ProcessKind::Other => true,
                ProcessKind::Lynis => {
                    outcome.active_lynis = true;
                    false
                }
            },
        };

        if should_remove && fs::remove_file(path).is_ok() {
            outcome.removed_any = true;
        }
    }

    outcome
}

fn inspect_process_kind(pid: u32) -> ProcessKind {
    let proc_dir = PathBuf::from("/proc").join(pid.to_string());
    if !proc_dir.exists() {
        return ProcessKind::Missing;
    }

    let cmdline = fs::read(proc_dir.join("cmdline"))
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_default()
        .replace('\0', " ");
    let comm = fs::read_to_string(proc_dir.join("comm")).unwrap_or_default();
    let process_text = format!("{cmdline} {comm}").to_ascii_lowercase();

    if process_text.contains("lynis") {
        ProcessKind::Lynis
    } else {
        ProcessKind::Other
    }
}

fn is_effective_root() -> bool {
    let Ok(output) = Command::new("id").arg("-u").output() else {
        return false;
    };

    output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "0"
}

fn command_detail(stderr: &[u8], stdout: &[u8]) -> String {
    let stderr = String::from_utf8_lossy(stderr);
    if !stderr.trim().is_empty() {
        return stderr.trim().to_owned();
    }

    let stdout = String::from_utf8_lossy(stdout);
    if !stdout.trim().is_empty() {
        return stdout.trim().to_owned();
    }

    crate::i18n::tr_adapter_command_no_error_detail()
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct LynisReport {
    hostname: Option<String>,
    hardening_index: Option<u8>,
    tests_done: Option<usize>,
    warnings: Vec<LynisEntry>,
    suggestions: Vec<LynisEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LynisEntry {
    test_id: String,
    message: String,
    details: String,
    solution: Option<String>,
}

fn parse_report(text: &str) -> Result<LynisReport, String> {
    let mut report = LynisReport::default();

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };

        match key.trim() {
            "hostname" => report.hostname = normalize_optional(value),
            "hardening_index" => report.hardening_index = value.trim().parse::<u8>().ok(),
            "lynis_tests_done" => report.tests_done = value.trim().parse::<usize>().ok(),
            "warning[]" => {
                if let Some(entry) = parse_pipe_entry(value) {
                    report.warnings.push(entry);
                }
            }
            "suggestion[]" => {
                if let Some(entry) = parse_pipe_entry(value) {
                    report.suggestions.push(entry);
                }
            }
            _ => {}
        }
    }

    if report.hostname.is_none()
        && report.hardening_index.is_none()
        && report.warnings.is_empty()
        && report.suggestions.is_empty()
    {
        return Err(crate::i18n::tr_adapter_report_parse_failed("Lynis"));
    }

    Ok(report)
}

fn parse_pipe_entry(value: &str) -> Option<LynisEntry> {
    let mut parts = value.split('|');
    let test_id = parts.next()?.trim();
    let message = parts.next()?.trim();
    let details = parts.next().unwrap_or_default().trim();
    let solution = normalize_optional(parts.next().unwrap_or_default());

    if test_id.is_empty() || message.is_empty() {
        return None;
    }

    Some(LynisEntry {
        test_id: test_id.to_owned(),
        message: message.to_owned(),
        details: details.to_owned(),
        solution,
    })
}

fn normalize_optional(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty() && trimmed != "-").then(|| trimmed.to_owned())
}

fn report_to_findings(report: &LynisReport, host_root: &Path, mode: LynisMode) -> Vec<Finding> {
    let subject = report
        .hostname
        .clone()
        .unwrap_or_else(|| host_root.display().to_string());
    let hardening_index = report
        .hardening_index
        .map(|value| value.to_string())
        .unwrap_or_else(|| t!("app.server.not_available").into_owned());

    let mut findings = Vec::new();

    if !report.warnings.is_empty() {
        findings.push(Finding {
            id: String::from("lynis.host_warnings"),
            axis: Axis::HostHardening,
            severity: Severity::High,
            scope: Scope::Host,
            source: Source::Lynis,
            subject: subject.clone(),
            related_service: None,
            title: t!("finding.lynis.host_warnings.title").into_owned(),
            description: t!(
                "finding.lynis.host_warnings.description",
                count = report.warnings.len(),
                subject = subject.as_str(),
                index = hardening_index.as_str()
            )
            .into_owned(),
            why_risky: t!("finding.lynis.host_warnings.why").into_owned(),
            how_to_fix: t!("finding.lynis.host_warnings.fix").into_owned(),
            evidence: entry_evidence(&report.warnings, report, mode, "warnings_total"),
            remediation: RemediationKind::None,
        });
    }

    if !report.suggestions.is_empty() {
        findings.push(Finding {
            id: String::from("lynis.host_suggestions"),
            axis: Axis::HostHardening,
            severity: Severity::Low,
            scope: Scope::Host,
            source: Source::Lynis,
            subject: subject.clone(),
            related_service: None,
            title: t!("finding.lynis.host_suggestions.title").into_owned(),
            description: t!(
                "finding.lynis.host_suggestions.description",
                count = report.suggestions.len(),
                subject = subject.as_str(),
                index = hardening_index.as_str()
            )
            .into_owned(),
            why_risky: t!("finding.lynis.host_suggestions.why").into_owned(),
            how_to_fix: t!("finding.lynis.host_suggestions.fix").into_owned(),
            evidence: entry_evidence(&report.suggestions, report, mode, "suggestions_total"),
            remediation: RemediationKind::None,
        });
    }

    findings
}

fn entry_evidence(
    entries: &[LynisEntry],
    report: &LynisReport,
    mode: LynisMode,
    total_key: &str,
) -> BTreeMap<String, String> {
    let mut evidence = BTreeMap::from([(String::from(total_key), entries.len().to_string())]);
    evidence.insert(String::from("mode"), mode.as_evidence_value().to_owned());

    if let Some(hardening_index) = report.hardening_index {
        evidence.insert(String::from("hardening_index"), hardening_index.to_string());
    }
    if let Some(tests_done) = report.tests_done {
        evidence.insert(String::from("tests_done"), tests_done.to_string());
    }

    let sample_ids = entries
        .iter()
        .take(5)
        .map(|entry| entry.test_id.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    if !sample_ids.is_empty() {
        evidence.insert(String::from("sample_test_ids"), sample_ids);
    }

    let sample_messages = entries
        .iter()
        .take(3)
        .map(|entry| {
            if entry.details.is_empty() {
                entry.message.clone()
            } else {
                format!("{} ({})", entry.message, entry.details)
            }
        })
        .collect::<Vec<_>>()
        .join(" | ");
    if !sample_messages.is_empty() {
        evidence.insert(String::from("sample_messages"), sample_messages);
    }

    let sample_solutions = entries
        .iter()
        .filter_map(|entry| entry.solution.as_deref())
        .take(2)
        .collect::<Vec<_>>()
        .join(" | ");
    if !sample_solutions.is_empty() {
        evidence.insert(String::from("sample_solutions"), sample_solutions);
    }

    evidence
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn test_guard() -> std::sync::MutexGuard<'static, ()> {
        static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
        GUARD
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("test mutex should not be poisoned")
    }

    #[test]
    fn skips_when_host_scan_was_not_requested() {
        let output = scan(None);

        assert_eq!(
            output.status,
            AdapterStatus::Skipped(
                t!("adapter.reason.host_not_scanned", locale = "en").into_owned()
            )
        );
    }

    #[test]
    fn skips_when_host_root_is_not_live() {
        let output = scan(Some(Path::new("/snapshots/server-root")));

        assert_eq!(
            output.status,
            AdapterStatus::Skipped(t!("adapter.reason.live_host_only", locale = "en").into_owned())
        );
    }

    #[test]
    fn skips_live_host_when_not_root_to_avoid_auth_prompts() {
        let output = scan_with_effective_root(Some(Path::new("/")), false);

        assert_eq!(
            output.status,
            AdapterStatus::Skipped(
                t!("app.adapter.lynis_root_required_skipped", locale = "en").into_owned()
            )
        );
        assert!(output.findings.is_empty());
        assert!(output.warnings.is_empty());
    }

    #[test]
    fn summarizes_report_fixture_into_host_findings() {
        let report = parse_report(include_str!(
            "../../tests/fixtures/adapters/lynis-report.dat"
        ))
        .expect("fixture should parse");

        assert_eq!(report.hostname.as_deref(), Some("demo-host"));
        assert_eq!(report.hardening_index, Some(67));
        assert_eq!(report.warnings.len(), 2);
        assert_eq!(report.suggestions.len(), 1);

        let findings = report_to_findings(&report, Path::new("/"), LynisMode::Full);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].source, Source::Lynis);
        assert_eq!(findings[0].axis, Axis::HostHardening);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[1].severity, Severity::Low);
        assert_eq!(findings[0].subject, "demo-host");
        assert_eq!(
            findings[0]
                .evidence
                .get("sample_test_ids")
                .map(String::as_str),
            Some("AUTH-9286, SSH-7408")
        );
        assert_eq!(
            findings[1].evidence.get("mode").map(String::as_str),
            Some("full")
        );
    }

    #[test]
    fn detect_lynis_reports_missing_for_unknown_binary() {
        let status = detect_lynis_with_command("hostveil-nonexistent-lynis");
        assert_eq!(status, LynisAvailability::Missing);
    }

    #[test]
    fn detect_lynis_reports_failed_for_non_zero_command() {
        let status = detect_lynis_with_command("false");
        assert!(matches!(status, LynisAvailability::Failed(_)));
    }

    #[test]
    fn detect_lynis_reports_available_for_true_command() {
        let status = detect_lynis_with_command("true");
        assert_eq!(status, LynisAvailability::Available);
    }

    #[test]
    fn cleanup_stale_pid_files_removes_dead_pid_files() {
        let _guard = test_guard();
        let pid_path = env::temp_dir().join("hostveil-lynis-stale-dead.pid");
        fs::write(&pid_path, "424242").expect("pid file should be written");

        let outcome =
            cleanup_stale_pid_files(std::slice::from_ref(&pid_path), |_| ProcessKind::Missing);

        assert!(outcome.removed_any);
        assert!(!outcome.active_lynis);
        assert!(!pid_path.exists());
    }

    #[test]
    fn cleanup_stale_pid_files_removes_invalid_pid_content() {
        let _guard = test_guard();
        let pid_path = env::temp_dir().join("hostveil-lynis-stale-invalid.pid");
        fs::write(&pid_path, "not-a-pid").expect("pid file should be written");

        let outcome =
            cleanup_stale_pid_files(std::slice::from_ref(&pid_path), |_| ProcessKind::Missing);

        assert!(outcome.removed_any);
        assert!(!outcome.active_lynis);
        assert!(!pid_path.exists());
    }

    #[test]
    fn cleanup_stale_pid_files_removes_non_lynis_process_lock() {
        let _guard = test_guard();
        let pid_path = env::temp_dir().join("hostveil-lynis-other-process.pid");
        fs::write(&pid_path, "1234").expect("pid file should be written");

        let outcome =
            cleanup_stale_pid_files(std::slice::from_ref(&pid_path), |_| ProcessKind::Other);

        assert!(outcome.removed_any);
        assert!(!outcome.active_lynis);
        assert!(!pid_path.exists());
    }

    #[test]
    fn cleanup_stale_pid_files_keeps_live_lynis_lock() {
        let _guard = test_guard();
        let pid_path = env::temp_dir().join("hostveil-lynis-live.pid");
        fs::write(&pid_path, "5678").expect("pid file should be written");

        let outcome =
            cleanup_stale_pid_files(std::slice::from_ref(&pid_path), |_| ProcessKind::Lynis);

        assert!(!outcome.removed_any);
        assert!(outcome.active_lynis);
        assert!(pid_path.exists());

        fs::remove_file(&pid_path).expect("test pid file should be cleaned up");
    }

    #[test]
    fn detects_pid_lockout_detail() {
        assert!(is_pid_lockout_detail(
            "Warning: PID file exists, probably another Lynis process is running."
        ));
        assert!(!is_pid_lockout_detail("some other failure"));
    }

    #[test]
    fn retries_after_removing_stale_pid_lock() {
        let _guard = test_guard();
        let test_dir = env::temp_dir().join("hostveil-lynis-retry-test");
        let _ = fs::remove_dir_all(&test_dir);
        fs::create_dir_all(&test_dir).expect("test dir should be created");

        let script_path = test_dir.join("fake-lynis.sh");
        let script = r#"#!/usr/bin/env bash
set -euo pipefail
count_file="$HOME/invocations"
count=0
if [[ -f "$count_file" ]]; then
  count="$(cat "$count_file")"
fi
count=$((count + 1))
printf '%s' "$count" > "$count_file"

if [[ "$1" == "--version" ]]; then
  exit 0
fi

report_file=""
while (($# > 0)); do
  case "$1" in
    --report-file)
      report_file="$2"
      shift 2
      ;;
    --logfile)
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

if [[ "$count" -eq 1 ]]; then
  printf '%s' '999999' > "$HOME/lynis.pid"
  printf '%s\n' 'Warning: PID file exists, probably another Lynis process is running.' >&2
  exit 1
fi

cat > "$report_file" <<'EOF'
hostname=test-host
hardening_index=67
lynis_tests_done=123
warning[]=AUTH-9286|Test warning|detail|solution
EOF
"#;
        fs::write(&script_path, script).expect("script should be written");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(&script_path)
                .expect("metadata should be readable")
                .permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&script_path, permissions)
                .expect("script should be made executable");
        }

        let original_home = env::var_os("HOME");
        let original_dir = env::current_dir().expect("current dir should exist");
        unsafe {
            env::set_var("HOME", &test_dir);
        }
        env::set_current_dir(&test_dir).expect("current dir should switch");

        let temp_files = LynisTempFiles {
            report_file: test_dir.join("report.dat"),
            log_file: test_dir.join("lynis.log"),
        };
        let result = run_lynis_with_command(
            script_path.to_str().expect("script path should be utf-8"),
            &temp_files,
            Duration::from_secs(5),
        )
        .expect("retry should succeed");

        if let Some(home) = original_home {
            unsafe {
                env::set_var("HOME", home);
            }
        }
        env::set_current_dir(original_dir).expect("current dir should restore");

        assert!(result.success);
        assert!(!test_dir.join("lynis.pid").exists());

        let _ = fs::remove_dir_all(&test_dir);
    }
}
