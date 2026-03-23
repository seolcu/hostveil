use std::path::PathBuf;

use super::AppError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    Tui,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppConfig {
    pub output_mode: OutputMode,
    pub show_help: bool,
    pub compose_path: Option<PathBuf>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            output_mode: OutputMode::Tui,
            show_help: false,
            compose_path: None,
        }
    }
}

impl AppConfig {
    pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, AppError> {
        let mut config = Self::default();
        let mut args = args.into_iter();

        while let Some(argument) = args.next() {
            match argument.as_str() {
                "--json" => config.output_mode = OutputMode::Json,
                "-h" | "--help" => config.show_help = true,
                "--compose" => {
                    let value = args
                        .next()
                        .ok_or(AppError::MissingArgumentValue("--compose"))?;
                    config.compose_path = Some(PathBuf::from(value));
                }
                _ if argument.starts_with("--compose=") => {
                    let value = argument.trim_start_matches("--compose=");
                    if value.is_empty() {
                        return Err(AppError::MissingArgumentValue("--compose"));
                    }
                    config.compose_path = Some(PathBuf::from(value));
                }
                _ => return Err(AppError::UnknownArgument(argument)),
            }
        }

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::{AppConfig, OutputMode};

    #[test]
    fn defaults_to_tui_mode() {
        let config = AppConfig::parse(Vec::<String>::new()).expect("config should parse");

        assert_eq!(config.output_mode, OutputMode::Tui);
        assert!(!config.show_help);
    }

    #[test]
    fn parses_json_flag() {
        let config = AppConfig::parse([String::from("--json")]).expect("config should parse");

        assert_eq!(config.output_mode, OutputMode::Json);
    }

    #[test]
    fn parses_compose_path_flag() {
        let config = AppConfig::parse([
            String::from("--compose"),
            String::from("docker-compose.yml"),
        ])
        .expect("config should parse");

        assert_eq!(
            config.compose_path.as_deref(),
            Some(std::path::Path::new("docker-compose.yml"))
        );
    }

    #[test]
    fn parses_inline_compose_path_flag() {
        let config =
            AppConfig::parse([String::from("--compose=stack")]).expect("config should parse");

        assert_eq!(
            config.compose_path.as_deref(),
            Some(std::path::Path::new("stack"))
        );
    }

    #[test]
    fn parses_help_flag() {
        let config = AppConfig::parse([String::from("--help")]).expect("config should parse");

        assert!(config.show_help);
    }
}
