use std::env;
use std::io;

use crate::compose::ComposeParseError;
use crate::settings;

pub const DEFAULT_LOCALE: &str = "en";

pub fn initialize_locale_from_args(args: &[String]) {
    let cli_locale = locale_override_from_args(args);
    initialize_locale(cli_locale.as_deref());
}

pub fn initialize_locale(cli_locale: Option<&str>) {
    let configured_locale = settings::load().locale;
    let hostveil_locale = env::var("HOSTVEIL_LOCALE").ok();

    rust_i18n::set_locale(resolve_preferred_locale(
        cli_locale,
        configured_locale.as_deref(),
        hostveil_locale.as_deref(),
    ));
}

pub fn locale_override_from_args(args: &[String]) -> Option<String> {
    let mut args = args.iter();

    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--locale" => {
                let value = args.next()?;
                return parse_supported_locale(value).map(str::to_owned);
            }
            _ if argument.starts_with("--locale=") => {
                let value = argument.trim_start_matches("--locale=");
                return parse_supported_locale(value).map(str::to_owned);
            }
            _ => {}
        }
    }

    None
}

pub fn parse_supported_locale(raw: &str) -> Option<&'static str> {
    normalize_locale_tag(raw)
}

pub fn current_locale() -> String {
    rust_i18n::locale().to_string()
}

pub fn cycle_persisted_locale() -> io::Result<&'static str> {
    let next = match &*rust_i18n::locale() {
        "ko" => "en",
        _ => "ko",
    };

    rust_i18n::set_locale(next);
    settings::persist_locale(next)?;
    Ok(next)
}

fn resolve_preferred_locale(
    cli_locale: Option<&str>,
    configured_locale: Option<&str>,
    hostveil_locale: Option<&str>,
) -> &'static str {
    [cli_locale, hostveil_locale, configured_locale]
        .into_iter()
        .flatten()
        .find_map(parse_supported_locale)
        .unwrap_or(DEFAULT_LOCALE)
}

fn normalize_locale_tag(raw: &str) -> Option<&'static str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let without_codeset = trimmed.split_once('.').map_or(trimmed, |(head, _)| head);
    let without_modifier = without_codeset
        .split_once('@')
        .map_or(without_codeset, |(head, _)| head);
    let language = without_modifier.replace('_', "-").to_ascii_lowercase();

    if language == "c" || language == "posix" {
        return Some(DEFAULT_LOCALE);
    }

    if language.starts_with("ko") {
        Some("ko")
    } else if language.starts_with("en") {
        Some(DEFAULT_LOCALE)
    } else {
        None
    }
}

pub fn tr(key: &str) -> String {
    match key {
        "app.name" => t!("app.name").into_owned(),
        "app.status.bootstrap" => t!("app.status.bootstrap").into_owned(),
        "app.status.no_target" => t!("app.status.no_target").into_owned(),
        "app.help.text" => t!("app.help.text").into_owned(),
        "app.hint.quit" => t!("app.hint.quit").into_owned(),
        "app.hint.json" => t!("app.hint.json").into_owned(),
        "app.panel.status" => t!("app.panel.status").into_owned(),
        "app.panel.hints" => t!("app.panel.hints").into_owned(),
        "app.summary.title" => t!("app.summary.title").into_owned(),
        "app.summary.none" => t!("app.summary.none").into_owned(),
        "app.panel.next_steps" => t!("app.panel.next_steps").into_owned(),
        "app.panel.next_step_one" => t!("app.panel.next_step_one").into_owned(),
        "app.panel.next_step_two" => t!("app.panel.next_step_two").into_owned(),
        "app.panel.next_step_three" => t!("app.panel.next_step_three").into_owned(),
        _ => t!("app.error.missing_translation", key = key).into_owned(),
    }
}

pub fn tr_unknown_argument(argument: &str) -> String {
    t!("app.error.unknown_argument", argument = argument).into_owned()
}

pub fn tr_version(name: &str, version: &str) -> String {
    t!("app.version.text", name = name, version = version).into_owned()
}

pub fn tr_missing_argument_value(flag: &str) -> String {
    t!("app.error.missing_argument_value", flag = flag).into_owned()
}

pub fn tr_invalid_argument_combination(message: &str) -> String {
    t!("app.error.invalid_argument_combination", message = message).into_owned()
}

pub fn tr_auto_upgrade_mode_required() -> String {
    t!("app.validation.auto_upgrade_mode_required").into_owned()
}

pub fn tr_fix_requires_target() -> String {
    t!("app.validation.fix_requires_target").into_owned()
}

pub fn tr_fix_host_root_not_supported() -> String {
    t!("app.validation.fix_host_root_not_supported").into_owned()
}

pub fn tr_fix_compose_conflict() -> String {
    t!("app.validation.fix_compose_conflict").into_owned()
}

pub fn tr_fix_json_not_supported() -> String {
    t!("app.validation.fix_json_not_supported").into_owned()
}

pub fn tr_preview_yes_requires_fix_mode() -> String {
    t!("app.validation.preview_yes_requires_fix_mode").into_owned()
}

pub fn tr_fix_mode_conflict() -> String {
    t!("app.validation.fix_mode_conflict").into_owned()
}

pub fn tr_unsupported_locale(value: &str) -> String {
    t!("app.validation.unsupported_locale", value = value).into_owned()
}

pub fn tr_duplicate_locale_override() -> String {
    t!("app.validation.duplicate_locale_override").into_owned()
}

pub fn tr_unsupported_setup_tool(value: &str) -> String {
    t!("app.validation.unsupported_setup_tool", value = value).into_owned()
}

pub fn tr_setup_tools_required() -> String {
    t!("app.validation.setup_tools_required").into_owned()
}

pub fn tr_unsupported_adapter(value: &str) -> String {
    t!("app.validation.unsupported_adapter", value = value).into_owned()
}

pub fn tr_adapter_selection_required() -> String {
    t!("app.validation.adapter_selection_required").into_owned()
}

pub fn tr_adapter_selection_keyword_conflict() -> String {
    t!("app.validation.adapter_selection_keyword_conflict").into_owned()
}

pub fn tr_adapters_require_scan_mode() -> String {
    t!("app.validation.adapters_require_scan_mode").into_owned()
}

pub fn tr_lifecycle_command_requires_installed_wrapper(command: &str) -> String {
    t!(
        "app.error.lifecycle_requires_installed_wrapper",
        command = command
    )
    .into_owned()
}

pub fn tr_compose_parse_error(error: &ComposeParseError) -> String {
    match error {
        ComposeParseError::ComposePathMissing { path } => t!(
            "app.error.compose_path_missing",
            path = path.display().to_string()
        )
        .into_owned(),
        ComposeParseError::ComposeFileNotFound { path } => t!(
            "app.error.compose_file_not_found",
            path = path.display().to_string()
        )
        .into_owned(),
        ComposeParseError::MalformedYaml { path, message } => t!(
            "app.error.compose_malformed_yaml",
            path = path.display().to_string(),
            message = message
        )
        .into_owned(),
        ComposeParseError::MissingServices { path } => t!(
            "app.error.compose_missing_services",
            path = path.display().to_string()
        )
        .into_owned(),
        ComposeParseError::Io { path, message } => t!(
            "app.error.compose_io",
            path = path.display().to_string(),
            message = message
        )
        .into_owned(),
    }
}

pub fn tr_io_error(message: &str) -> String {
    t!("app.error.io", message = message).into_owned()
}

pub fn tr_tui_requires_terminal() -> String {
    t!("app.error.tui_requires_terminal").into_owned()
}

pub fn tr_fix_requires_terminal() -> String {
    t!("app.error.fix_requires_terminal").into_owned()
}

pub fn tr_status_compose_loaded(path: &str, count: usize) -> String {
    t!("app.status.compose_loaded", path = path, count = count).into_owned()
}

pub fn tr_status_host_loaded(path: &str) -> String {
    t!("app.status.host_loaded", path = path).into_owned()
}

pub fn tr_status_compose_and_host_loaded(path: &str, count: usize) -> String {
    t!(
        "app.status.compose_and_host_loaded",
        path = path,
        count = count
    )
    .into_owned()
}

pub fn tr_summary_compose_file(path: &str) -> String {
    t!("app.summary.compose_file", path = path).into_owned()
}

pub fn tr_summary_compose_root(path: &str) -> String {
    t!("app.summary.compose_root", path = path).into_owned()
}

pub fn tr_summary_host_root(path: &str) -> String {
    t!("app.summary.host_root", path = path).into_owned()
}

pub fn tr_summary_loaded_files(count: usize) -> String {
    t!("app.summary.loaded_files", count = count).into_owned()
}

pub fn tr_summary_service_count(count: usize) -> String {
    t!("app.summary.service_count", count = count).into_owned()
}

pub fn tr_summary_overall_score(score: u8) -> String {
    t!("app.summary.overall_score", score = score).into_owned()
}

pub fn tr_summary_finding_count(count: usize) -> String {
    t!("app.summary.finding_count", count = count).into_owned()
}

pub fn tr_setup_requires_terminal_or_explicit_tools() -> String {
    t!("app.setup.error.requires_terminal_or_explicit_tools").into_owned()
}

pub fn tr_setup_sudo_missing() -> String {
    t!("app.setup.error.sudo_missing").into_owned()
}

pub fn tr_setup_sudo_needs_terminal() -> String {
    t!("app.setup.error.sudo_needs_terminal").into_owned()
}

pub fn tr_setup_sudo_credentials_failed(error: &str) -> String {
    t!("app.setup.error.sudo_credentials_failed", error = error).into_owned()
}

pub fn tr_adapter_scan_failed(tool: &str, image: &str, error: &str) -> String {
    t!(
        "app.adapter.scan_failed",
        tool = tool,
        image = image,
        error = error
    )
    .into_owned()
}

pub fn tr_adapter_json_parse_failed(tool: &str, error: &str) -> String {
    t!("app.adapter.json_parse_failed", tool = tool, error = error).into_owned()
}

pub fn tr_adapter_command_no_error_detail() -> String {
    t!("app.adapter.command_no_error_detail").into_owned()
}

pub fn tr_adapter_command_timed_out(seconds: u64) -> String {
    t!("app.adapter.command_timed_out", seconds = seconds).into_owned()
}

pub fn tr_adapter_report_parse_failed(tool: &str) -> String {
    t!("app.adapter.report_parse_failed", tool = tool).into_owned()
}

pub fn tr_adapter_scan_thread_panicked(adapter: &str) -> String {
    t!("app.adapter.scan_thread_panicked", adapter = adapter).into_owned()
}

pub fn tr_discovery_docker_cli_missing_fallback() -> String {
    t!("app.discovery.docker_cli_missing_fallback").into_owned()
}

pub fn tr_discovery_docker_failed_fallback() -> String {
    t!("app.discovery.docker_failed_fallback").into_owned()
}

pub fn tr_discovery_docker_failed_detail(detail: &str) -> String {
    t!("app.discovery.docker_failed_detail", detail = detail).into_owned()
}

pub fn tr_discovery_no_projects_current_dir() -> String {
    t!("app.discovery.no_projects_current_dir").into_owned()
}

pub fn tr_discovery_recovered_missing_compose_path(
    project: &str,
    compose_path: &str,
    working_dir: &str,
) -> String {
    t!(
        "app.discovery.recovered_missing_compose_path",
        project = project,
        compose_path = compose_path,
        working_dir = working_dir
    )
    .into_owned()
}

pub fn tr_discovery_missing_compose_path_and_fallback_failed(
    project: &str,
    compose_path: &str,
    working_dir: &str,
    error: &str,
) -> String {
    t!(
        "app.discovery.missing_compose_path_and_fallback_failed",
        project = project,
        compose_path = compose_path,
        working_dir = working_dir,
        error = error
    )
    .into_owned()
}

pub fn tr_discovery_missing_compose_path(project: &str, compose_path: &str) -> String {
    t!(
        "app.discovery.missing_compose_path",
        project = project,
        compose_path = compose_path
    )
    .into_owned()
}

pub fn tr_discovery_parse_failed(project: &str, error: &str) -> String {
    t!(
        "app.discovery.parse_failed",
        project = project,
        error = error
    )
    .into_owned()
}

pub fn tr_discovery_no_compose_file_in_working_dir(project: &str, working_dir: &str) -> String {
    t!(
        "app.discovery.no_compose_file_in_working_dir",
        project = project,
        working_dir = working_dir
    )
    .into_owned()
}

pub fn tr_discovery_parse_failed_in_working_dir(
    project: &str,
    working_dir: &str,
    error: &str,
) -> String {
    t!(
        "app.discovery.parse_failed_in_working_dir",
        project = project,
        working_dir = working_dir,
        error = error
    )
    .into_owned()
}

pub fn tr_discovery_no_usable_compose_path(project: &str) -> String {
    t!("app.discovery.no_usable_compose_path", project = project).into_owned()
}

pub fn tr_discovery_current_dir_fallback_used() -> String {
    t!("app.discovery.current_dir_fallback_used").into_owned()
}

pub fn tr_discovery_current_dir_fallback_failed(error: &str) -> String {
    t!("app.discovery.current_dir_fallback_failed", error = error).into_owned()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde_yaml::Value;

    use super::{
        locale_override_from_args, normalize_locale_tag, resolve_preferred_locale, tr,
        tr_compose_parse_error, tr_fix_requires_terminal, tr_invalid_argument_combination,
        tr_io_error, tr_lifecycle_command_requires_installed_wrapper, tr_missing_argument_value,
        tr_status_compose_and_host_loaded, tr_status_compose_loaded, tr_status_host_loaded,
        tr_summary_finding_count, tr_summary_host_root, tr_summary_overall_score,
        tr_summary_service_count, tr_tui_requires_terminal, tr_unknown_argument, tr_version,
    };
    use crate::compose::ComposeParseError;

    fn flatten_yaml_keys(value: &Value, prefix: &str, keys: &mut BTreeSet<String>) {
        if let Value::Mapping(mapping) = value {
            for (key, value) in mapping {
                let Value::String(key) = key else {
                    continue;
                };

                let next = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                keys.insert(next.clone());
                flatten_yaml_keys(value, &next, keys);
            }
        }
    }

    #[test]
    fn returns_known_translation() {
        assert_eq!(tr("app.name"), "hostveil");
    }

    #[test]
    fn returns_updated_no_target_copy() {
        assert_eq!(
            tr("app.status.no_target"),
            "No explicit target was provided. Run without arguments for live discovery, or pass --compose PATH / --host-root PATH for a targeted scan."
        );
    }

    #[test]
    fn formats_unknown_argument_message() {
        assert_eq!(tr_unknown_argument("--bad"), "unknown argument: --bad");
    }

    #[test]
    fn formats_version_message() {
        assert_eq!(
            tr_version("hostveil", "0.1.0-alpha.1"),
            "hostveil 0.1.0-alpha.1"
        );
    }

    #[test]
    fn falls_back_for_unknown_key() {
        assert_eq!(
            tr("does.not.exist"),
            "missing translation for key: does.not.exist"
        );
    }

    #[test]
    fn formats_io_error_message() {
        assert_eq!(tr_io_error("boom"), "application error: boom");
    }

    #[test]
    fn formats_tui_requires_terminal_message() {
        assert_eq!(
            tr_tui_requires_terminal(),
            "the interactive TUI requires a terminal; use --json for non-interactive runs"
        );
    }

    #[test]
    fn formats_fix_requires_terminal_message() {
        assert_eq!(
            tr_fix_requires_terminal(),
            "guided Compose fixes require a terminal review; use --preview-changes to inspect the diff non-interactively"
        );
    }

    #[test]
    fn formats_missing_argument_value_message() {
        assert_eq!(
            tr_missing_argument_value("--compose"),
            "missing value for argument: --compose"
        );
    }

    #[test]
    fn formats_invalid_argument_combination_message() {
        assert_eq!(
            tr_invalid_argument_combination("--json is not supported with fix operations"),
            "invalid argument combination: --json is not supported with fix operations"
        );
    }

    #[test]
    fn formats_lifecycle_wrapper_error_message() {
        assert_eq!(
            tr_lifecycle_command_requires_installed_wrapper("upgrade"),
            "upgrade is only available through the installed hostveil wrapper. Install first with: curl -fsSL https://raw.githubusercontent.com/seolcu/hostveil/main/scripts/install.sh | bash, then run: hostveil upgrade"
        );
    }

    #[test]
    fn formats_compose_error_message() {
        assert_eq!(
            tr_compose_parse_error(&ComposeParseError::MissingServices {
                path: std::path::PathBuf::from("/srv/docker-compose.yml"),
            }),
            "no services were found in /srv/docker-compose.yml"
        );
    }

    #[test]
    fn formats_compose_loaded_status() {
        assert_eq!(
            tr_status_compose_loaded("/srv/docker-compose.yml", 2),
            "Loaded 2 service(s) from /srv/docker-compose.yml"
        );
    }

    #[test]
    fn formats_host_loaded_status() {
        assert_eq!(
            tr_status_host_loaded("/snapshot"),
            "Loaded host checks from /snapshot"
        );
    }

    #[test]
    fn formats_compose_and_host_loaded_status() {
        assert_eq!(
            tr_status_compose_and_host_loaded("/srv/docker-compose.yml", 2),
            "Loaded 2 service(s) from /srv/docker-compose.yml with host checks enabled"
        );
    }

    #[test]
    fn formats_service_count_summary() {
        assert_eq!(tr_summary_service_count(3), "Service count: 3");
    }

    #[test]
    fn formats_host_root_summary() {
        assert_eq!(tr_summary_host_root("/snapshot"), "Host root: /snapshot");
    }

    #[test]
    fn formats_overall_score_summary() {
        assert_eq!(tr_summary_overall_score(74), "Overall score: 74");
    }

    #[test]
    fn formats_finding_count_summary() {
        assert_eq!(tr_summary_finding_count(4), "Finding count: 4");
    }

    #[test]
    fn locale_resolver_prefers_cli_override() {
        assert_eq!(
            resolve_preferred_locale(Some("ko_KR.UTF-8"), Some("en_US.UTF-8"), Some("en_US")),
            "ko"
        );
    }

    #[test]
    fn locale_resolver_prefers_hostveil_env_over_saved_locale() {
        assert_eq!(
            resolve_preferred_locale(None, Some("ko-KR"), Some("en_US.UTF-8")),
            "en"
        );
    }

    #[test]
    fn locale_resolver_uses_saved_locale_when_no_explicit_override_is_present() {
        assert_eq!(resolve_preferred_locale(None, Some("ko-KR"), None), "ko");
    }

    #[test]
    fn locale_resolver_falls_back_to_english_for_unknown_values() {
        assert_eq!(
            resolve_preferred_locale(Some("fr_FR.UTF-8"), Some("de_DE"), Some("es_ES")),
            "en"
        );
        assert_eq!(resolve_preferred_locale(Some("C.UTF-8"), None, None), "en");
    }

    #[test]
    fn locale_tag_parser_handles_common_variants() {
        assert_eq!(normalize_locale_tag("ko_KR.UTF-8"), Some("ko"));
        assert_eq!(normalize_locale_tag("en-US"), Some("en"));
        assert_eq!(normalize_locale_tag("POSIX"), Some("en"));
        assert_eq!(normalize_locale_tag(""), None);
    }

    #[test]
    fn locale_override_parser_detects_flag_forms() {
        assert_eq!(
            locale_override_from_args(&[
                String::from("--locale"),
                String::from("ko_KR.UTF-8"),
                String::from("--json"),
            ]),
            Some(String::from("ko"))
        );
        assert_eq!(
            locale_override_from_args(&[String::from("--locale=en")]),
            Some(String::from("en"))
        );
    }

    #[test]
    fn korean_locale_translates_cli_and_tui_strings() {
        assert_eq!(t!("app.help.usage", locale = "ko").into_owned(), "사용법");
        assert_eq!(
            t!("app.hint.quit", locale = "ko").into_owned(),
            "q 또는 Esc를 눌러 종료"
        );
    }

    #[test]
    fn korean_locale_translates_finding_badges_and_short_labels() {
        assert_eq!(
            t!("app.finding.severity_short.critical", locale = "ko").into_owned(),
            "치명"
        );
        assert_eq!(
            t!("app.finding.remediation_badge.guided", locale = "ko").into_owned(),
            "가이드"
        );
        assert_eq!(
            t!("app.finding.remediation_badge_compact.safe", locale = "ko").into_owned(),
            "안"
        );
    }

    #[test]
    fn korean_locale_falls_back_to_english_for_missing_keys() {
        assert_eq!(
            t!("test.fallback_probe", locale = "ko").into_owned(),
            "English fallback probe"
        );
    }

    #[test]
    fn locale_files_keep_en_and_ko_keys_in_sync() {
        let en: Value =
            serde_yaml::from_str(include_str!("../../locales/en.yml")).expect("en locale parses");
        let ko: Value =
            serde_yaml::from_str(include_str!("../../locales/ko.yml")).expect("ko locale parses");

        let mut en_keys = BTreeSet::new();
        let mut ko_keys = BTreeSet::new();
        flatten_yaml_keys(&en, "", &mut en_keys);
        flatten_yaml_keys(&ko, "", &mut ko_keys);

        assert_eq!(en_keys, ko_keys, "locale keys must stay in sync");
    }
}
