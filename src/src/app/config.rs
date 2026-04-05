use std::path::PathBuf;

use super::AppError;
use crate::fix::FixMode;

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
    pub host_root: Option<PathBuf>,
    pub fix_mode: Option<FixMode>,
    pub fix_target_path: Option<PathBuf>,
    pub preview_changes: bool,
    pub assume_yes: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            output_mode: OutputMode::Tui,
            show_help: false,
            compose_path: None,
            host_root: None,
            fix_mode: None,
            fix_target_path: None,
            preview_changes: false,
            assume_yes: false,
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
                "--preview-changes" => config.preview_changes = true,
                "--yes" => config.assume_yes = true,
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
                "--host-root" => {
                    let value = args
                        .next()
                        .ok_or(AppError::MissingArgumentValue("--host-root"))?;
                    config.host_root = Some(PathBuf::from(value));
                }
                _ if argument.starts_with("--host-root=") => {
                    let value = argument.trim_start_matches("--host-root=");
                    if value.is_empty() {
                        return Err(AppError::MissingArgumentValue("--host-root"));
                    }
                    config.host_root = Some(PathBuf::from(value));
                }
                "--quick-fix" => {
                    let value = args
                        .next()
                        .ok_or(AppError::MissingArgumentValue("--quick-fix"))?;
                    config.set_fix_target(FixMode::QuickFix, PathBuf::from(value))?;
                }
                _ if argument.starts_with("--quick-fix=") => {
                    let value = argument.trim_start_matches("--quick-fix=");
                    if value.is_empty() {
                        return Err(AppError::MissingArgumentValue("--quick-fix"));
                    }
                    config.set_fix_target(FixMode::QuickFix, PathBuf::from(value))?;
                }
                "--fix" => {
                    let value = args.next().ok_or(AppError::MissingArgumentValue("--fix"))?;
                    config.set_fix_target(FixMode::Fix, PathBuf::from(value))?;
                }
                _ if argument.starts_with("--fix=") => {
                    let value = argument.trim_start_matches("--fix=");
                    if value.is_empty() {
                        return Err(AppError::MissingArgumentValue("--fix"));
                    }
                    config.set_fix_target(FixMode::Fix, PathBuf::from(value))?;
                }
                _ => return Err(AppError::UnknownArgument(argument)),
            }
        }

        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), AppError> {
        if self.fix_mode.is_some() {
            if self.fix_target_path.is_none() {
                return Err(AppError::InvalidArgumentCombination(String::from(
                    "a compose target is required for fix operations",
                )));
            }
            if self.host_root.is_some() {
                return Err(AppError::InvalidArgumentCombination(String::from(
                    "--host-root is not supported with fix operations",
                )));
            }
            if self.compose_path.is_some() {
                return Err(AppError::InvalidArgumentCombination(String::from(
                    "use --quick-fix PATH or --fix PATH instead of combining them with --compose",
                )));
            }
            if self.output_mode == OutputMode::Json {
                return Err(AppError::InvalidArgumentCombination(String::from(
                    "--json is not supported with fix operations",
                )));
            }
        } else if self.preview_changes || self.assume_yes {
            return Err(AppError::InvalidArgumentCombination(String::from(
                "--preview-changes and --yes are only valid with --quick-fix or --fix",
            )));
        }

        Ok(())
    }

    fn set_fix_target(&mut self, mode: FixMode, path: PathBuf) -> Result<(), AppError> {
        if self.fix_mode.is_some() {
            return Err(AppError::InvalidArgumentCombination(String::from(
                "choose only one of --quick-fix or --fix",
            )));
        }

        self.fix_mode = Some(mode);
        self.fix_target_path = Some(path);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{AppConfig, OutputMode};
    use crate::fix::FixMode;

    #[test]
    fn defaults_to_tui_mode() {
        let config = AppConfig::parse(Vec::<String>::new()).expect("config should parse");

        assert_eq!(config.output_mode, OutputMode::Tui);
        assert!(!config.show_help);
        assert!(config.fix_mode.is_none());
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

    #[test]
    fn parses_host_root_flag() {
        let config = AppConfig::parse([String::from("--host-root"), String::from("/snapshot")])
            .expect("config should parse");

        assert_eq!(
            config.host_root.as_deref(),
            Some(std::path::Path::new("/snapshot"))
        );
    }

    #[test]
    fn parses_inline_host_root_flag() {
        let config =
            AppConfig::parse([String::from("--host-root=/snapshot")]).expect("config should parse");

        assert_eq!(
            config.host_root.as_deref(),
            Some(std::path::Path::new("/snapshot"))
        );
    }

    #[test]
    fn parses_quick_fix_mode() {
        let config = AppConfig::parse([
            String::from("--quick-fix"),
            String::from("docker-compose.yml"),
            String::from("--preview-changes"),
        ])
        .expect("config should parse");

        assert_eq!(config.fix_mode, Some(FixMode::QuickFix));
        assert_eq!(
            config.fix_target_path.as_deref(),
            Some(std::path::Path::new("docker-compose.yml"))
        );
        assert!(config.preview_changes);
    }

    #[test]
    fn parses_inline_fix_mode() {
        let config = AppConfig::parse([String::from("--fix=stack"), String::from("--yes")])
            .expect("config should parse");

        assert_eq!(config.fix_mode, Some(FixMode::Fix));
        assert_eq!(
            config.fix_target_path.as_deref(),
            Some(std::path::Path::new("stack"))
        );
        assert!(config.assume_yes);
    }

    #[test]
    fn rejects_json_with_fix_mode() {
        let error = AppConfig::parse([
            String::from("--quick-fix"),
            String::from("docker-compose.yml"),
            String::from("--json"),
        ])
        .expect_err("config should reject incompatible flags");

        assert!(matches!(
            error,
            super::AppError::InvalidArgumentCombination(_)
        ));
    }

    #[test]
    fn rejects_preview_without_fix_mode() {
        let error = AppConfig::parse([String::from("--preview-changes")])
            .expect_err("preview should require fix mode");

        assert!(matches!(
            error,
            super::AppError::InvalidArgumentCombination(_)
        ));
    }
}
