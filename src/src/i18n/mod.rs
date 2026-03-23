use crate::compose::ComposeParseError;

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

pub fn tr_missing_argument_value(flag: &str) -> String {
    t!("app.error.missing_argument_value", flag = flag).into_owned()
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

pub fn tr_status_compose_loaded(path: &str, count: usize) -> String {
    t!("app.status.compose_loaded", path = path, count = count).into_owned()
}

pub fn tr_summary_compose_file(path: &str) -> String {
    t!("app.summary.compose_file", path = path).into_owned()
}

pub fn tr_summary_compose_root(path: &str) -> String {
    t!("app.summary.compose_root", path = path).into_owned()
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
        tr, tr_compose_parse_error, tr_io_error, tr_missing_argument_value,
        tr_status_compose_loaded, tr_summary_finding_count, tr_summary_overall_score,
        tr_summary_service_count, tr_unknown_argument,
    };
    use crate::compose::ComposeParseError;

    #[test]
    fn returns_known_translation() {
        assert_eq!(tr("app.name"), "hostveil");
    }

    #[test]
    fn formats_unknown_argument_message() {
        assert_eq!(tr_unknown_argument("--bad"), "unknown argument: --bad");
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
    fn formats_missing_argument_value_message() {
        assert_eq!(
            tr_missing_argument_value("--compose"),
            "missing value for argument: --compose"
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
    fn formats_service_count_summary() {
        assert_eq!(tr_summary_service_count(3), "Service count: 3");
    }

    #[test]
    fn formats_overall_score_summary() {
        assert_eq!(tr_summary_overall_score(74), "Overall score: 74");
    }

    #[test]
    fn formats_finding_count_summary() {
        assert_eq!(tr_summary_finding_count(4), "Finding count: 4");
    }
}
