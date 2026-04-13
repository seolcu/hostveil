use std::env;

use crate::compose::ComposeParseError;

pub fn initialize_locale_from_env() {
    let hostveil_locale = env::var("HOSTVEIL_LOCALE").ok();
    let lc_all = env::var("LC_ALL").ok();
    let lang = env::var("LANG").ok();

    rust_i18n::set_locale(resolve_preferred_locale(
        hostveil_locale.as_deref(),
        lc_all.as_deref(),
        lang.as_deref(),
    ));
}

fn resolve_preferred_locale(
    hostveil_locale: Option<&str>,
    lc_all: Option<&str>,
    lang: Option<&str>,
) -> &'static str {
    [hostveil_locale, lc_all, lang]
        .into_iter()
        .flatten()
        .find_map(normalize_locale_tag)
        .unwrap_or("en")
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
        return Some("en");
    }

    if language.starts_with("ko") {
        Some("ko")
    } else if language.starts_with("en") {
        Some("en")
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

#[cfg(test)]
mod tests {
    use super::{
        normalize_locale_tag, resolve_preferred_locale, tr, tr_compose_parse_error,
        tr_fix_requires_terminal, tr_invalid_argument_combination, tr_io_error,
        tr_lifecycle_command_requires_installed_wrapper, tr_missing_argument_value,
        tr_status_compose_and_host_loaded, tr_status_compose_loaded, tr_status_host_loaded,
        tr_summary_finding_count, tr_summary_host_root, tr_summary_overall_score,
        tr_summary_service_count, tr_tui_requires_terminal, tr_unknown_argument, tr_version,
    };
    use crate::compose::ComposeParseError;

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
            "upgrade is only available through an installed hostveil wrapper; install hostveil first with the installer script"
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
    fn locale_resolver_prefers_explicit_hostveil_locale() {
        assert_eq!(
            resolve_preferred_locale(Some("ko_KR.UTF-8"), Some("en_US.UTF-8"), Some("en_US")),
            "ko"
        );
    }

    #[test]
    fn locale_resolver_uses_system_locale_when_explicit_locale_is_missing() {
        assert_eq!(
            resolve_preferred_locale(None, Some("ko-KR"), Some("en_US.UTF-8")),
            "ko"
        );
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
    fn korean_locale_translates_cli_and_tui_strings() {
        assert_eq!(t!("app.help.usage", locale = "ko").into_owned(), "사용법");
        assert_eq!(
            t!("app.hint.quit", locale = "ko").into_owned(),
            "q 또는 Esc를 눌러 종료"
        );
    }

    #[test]
    fn korean_locale_falls_back_to_english_for_missing_keys() {
        assert_eq!(
            t!("test.fallback_probe", locale = "ko").into_owned(),
            "English fallback probe"
        );
    }
}
