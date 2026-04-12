use std::path::PathBuf;

use super::AppError;
use crate::fix::FixMode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    Tui,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleCommand {
    Upgrade,
    Uninstall,
    AutoUpgradeEnable,
    AutoUpgradeDisable,
}

impl LifecycleCommand {
    pub fn name(self) -> &'static str {
        match self {
            Self::Upgrade => "upgrade",
            Self::Uninstall => "uninstall",
            Self::AutoUpgradeEnable | Self::AutoUpgradeDisable => "auto-upgrade",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SetupTool {
    Lynis,
    Trivy,
    Fail2Ban,
}

impl SetupTool {
    pub const ALL: [Self; 3] = [Self::Lynis, Self::Trivy, Self::Fail2Ban];

    pub fn from_arg(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "lynis" => Some(Self::Lynis),
            "trivy" => Some(Self::Trivy),
            "fail2ban" => Some(Self::Fail2Ban),
            _ => None,
        }
    }

    pub fn cli_name(self) -> &'static str {
        match self {
            Self::Lynis => "lynis",
            Self::Trivy => "trivy",
            Self::Fail2Ban => "fail2ban",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SetupConfig {
    pub selected_tools: Option<Vec<SetupTool>>,
    pub assume_yes: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppConfig {
    pub output_mode: OutputMode,
    pub show_help: bool,
    pub show_version: bool,
    pub lifecycle_command: Option<LifecycleCommand>,
    pub setup_command: Option<SetupConfig>,
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
            show_version: false,
            lifecycle_command: None,
            setup_command: None,
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
        let args: Vec<String> = args.into_iter().collect();

        if let Some(command) = args.first() {
            match command.as_str() {
                "setup" => return Self::parse_setup(args.into_iter().skip(1)),
                "upgrade" => return Self::parse_upgrade(args.into_iter().skip(1)),
                "uninstall" => return Self::parse_uninstall(args.into_iter().skip(1)),
                "auto-upgrade" => return Self::parse_auto_upgrade(args.into_iter().skip(1)),
                _ => {}
            }
        }

        let mut config = Self::default();
        let mut args = args.into_iter();

        while let Some(argument) = args.next() {
            match argument.as_str() {
                "--json" => config.output_mode = OutputMode::Json,
                "-h" | "--help" => config.show_help = true,
                "-V" | "--version" => config.show_version = true,
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

    fn parse_setup(args: impl IntoIterator<Item = String>) -> Result<Self, AppError> {
        let mut config = Self::default();
        let mut setup = SetupConfig::default();
        let mut selected_tools = Vec::new();
        let mut args = args.into_iter();

        while let Some(argument) = args.next() {
            match argument.as_str() {
                "--yes" => setup.assume_yes = true,
                "--tool" => {
                    let value = args
                        .next()
                        .ok_or(AppError::MissingArgumentValue("--tool"))?;
                    push_setup_tool(&mut selected_tools, &value)?;
                }
                _ if argument.starts_with("--tool=") => {
                    let value = argument.trim_start_matches("--tool=");
                    if value.is_empty() {
                        return Err(AppError::MissingArgumentValue("--tool"));
                    }
                    push_setup_tool(&mut selected_tools, value)?;
                }
                "--tools" => {
                    let value = args
                        .next()
                        .ok_or(AppError::MissingArgumentValue("--tools"))?;
                    parse_setup_tool_list(&mut selected_tools, &value)?;
                }
                _ if argument.starts_with("--tools=") => {
                    let value = argument.trim_start_matches("--tools=");
                    if value.is_empty() {
                        return Err(AppError::MissingArgumentValue("--tools"));
                    }
                    parse_setup_tool_list(&mut selected_tools, value)?;
                }
                "-h" | "--help" => config.show_help = true,
                _ => return Err(AppError::UnknownArgument(argument)),
            }
        }

        if !selected_tools.is_empty() {
            setup.selected_tools = Some(selected_tools);
        }
        config.setup_command = Some(setup);
        config.validate()?;
        Ok(config)
    }

    fn parse_upgrade(args: impl IntoIterator<Item = String>) -> Result<Self, AppError> {
        let mut config = Self::default();
        let mut args = args.into_iter();

        while let Some(argument) = args.next() {
            match argument.as_str() {
                "--version" => {
                    args.next()
                        .ok_or(AppError::MissingArgumentValue("--version"))?;
                }
                _ if argument.starts_with("--version=") => {
                    let value = argument.trim_start_matches("--version=");
                    if value.is_empty() {
                        return Err(AppError::MissingArgumentValue("--version"));
                    }
                }
                "--channel" => {
                    args.next()
                        .ok_or(AppError::MissingArgumentValue("--channel"))?;
                }
                _ if argument.starts_with("--channel=") => {
                    let value = argument.trim_start_matches("--channel=");
                    if value.is_empty() {
                        return Err(AppError::MissingArgumentValue("--channel"));
                    }
                }
                "-h" | "--help" => config.show_help = true,
                _ => return Err(AppError::UnknownArgument(argument)),
            }
        }

        config.lifecycle_command = Some(LifecycleCommand::Upgrade);
        config.validate()?;
        Ok(config)
    }

    fn parse_uninstall(args: impl IntoIterator<Item = String>) -> Result<Self, AppError> {
        let mut config = Self::default();

        for argument in args {
            match argument.as_str() {
                "-h" | "--help" => config.show_help = true,
                _ => return Err(AppError::UnknownArgument(argument)),
            }
        }

        config.lifecycle_command = Some(LifecycleCommand::Uninstall);
        config.validate()?;
        Ok(config)
    }

    fn parse_auto_upgrade(args: impl IntoIterator<Item = String>) -> Result<Self, AppError> {
        let mut config = Self::default();
        let mut args = args.into_iter();

        let Some(mode) = args.next() else {
            return Err(AppError::InvalidArgumentCombination(String::from(
                "choose one of enable or disable for auto-upgrade",
            )));
        };

        let lifecycle_command = match mode.as_str() {
            "enable" => LifecycleCommand::AutoUpgradeEnable,
            "disable" => LifecycleCommand::AutoUpgradeDisable,
            "-h" | "--help" => {
                config.show_help = true;
                config.validate()?;
                return Ok(config);
            }
            _ => {
                return Err(AppError::InvalidArgumentCombination(String::from(
                    "choose one of enable or disable for auto-upgrade",
                )));
            }
        };

        for argument in args {
            match argument.as_str() {
                "-h" | "--help" => config.show_help = true,
                _ => return Err(AppError::UnknownArgument(argument)),
            }
        }

        config.lifecycle_command = Some(lifecycle_command);
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), AppError> {
        if self.setup_command.is_some() {
            return Ok(());
        }

        if self.lifecycle_command.is_some() {
            return Ok(());
        }

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

fn push_setup_tool(tools: &mut Vec<SetupTool>, value: &str) -> Result<(), AppError> {
    let tool = SetupTool::from_arg(value).ok_or_else(|| {
        AppError::InvalidArgumentCombination(format!("unsupported setup tool: {value}"))
    })?;
    if !tools.contains(&tool) {
        tools.push(tool);
    }
    Ok(())
}

fn parse_setup_tool_list(tools: &mut Vec<SetupTool>, value: &str) -> Result<(), AppError> {
    let mut parsed_any = false;

    for entry in value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        parsed_any = true;
        push_setup_tool(tools, entry)?;
    }

    if parsed_any {
        Ok(())
    } else {
        Err(AppError::InvalidArgumentCombination(String::from(
            "--tools requires at least one tool name",
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::{AppConfig, LifecycleCommand, OutputMode, SetupTool};
    use crate::fix::FixMode;

    #[test]
    fn defaults_to_tui_mode() {
        let config = AppConfig::parse(Vec::<String>::new()).expect("config should parse");

        assert_eq!(config.output_mode, OutputMode::Tui);
        assert!(!config.show_help);
        assert!(!config.show_version);
        assert!(config.lifecycle_command.is_none());
        assert!(config.setup_command.is_none());
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
    fn parses_version_flag() {
        let config = AppConfig::parse([String::from("--version")]).expect("config should parse");

        assert!(config.show_version);
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

    #[test]
    fn parses_upgrade_lifecycle_command() {
        let config = AppConfig::parse([
            String::from("upgrade"),
            String::from("--channel"),
            String::from("stable"),
            String::from("--version=v0.1.0"),
        ])
        .expect("upgrade command should parse");

        assert_eq!(config.lifecycle_command, Some(LifecycleCommand::Upgrade));
    }

    #[test]
    fn parses_uninstall_lifecycle_command() {
        let config =
            AppConfig::parse([String::from("uninstall")]).expect("uninstall command should parse");

        assert_eq!(config.lifecycle_command, Some(LifecycleCommand::Uninstall));
    }

    #[test]
    fn parses_auto_upgrade_enable_command() {
        let config = AppConfig::parse([String::from("auto-upgrade"), String::from("enable")])
            .expect("auto-upgrade enable should parse");

        assert_eq!(
            config.lifecycle_command,
            Some(LifecycleCommand::AutoUpgradeEnable)
        );
    }

    #[test]
    fn rejects_auto_upgrade_without_mode() {
        let error = AppConfig::parse([String::from("auto-upgrade")])
            .expect_err("auto-upgrade should require a mode");

        assert!(matches!(
            error,
            super::AppError::InvalidArgumentCombination(_)
        ));
    }

    #[test]
    fn parses_setup_command_with_explicit_tools() {
        let config = AppConfig::parse([
            String::from("setup"),
            String::from("--tools=lynis,fail2ban"),
            String::from("--tool"),
            String::from("trivy"),
            String::from("--yes"),
        ])
        .expect("setup command should parse");

        let setup = config
            .setup_command
            .expect("setup command should be captured");
        assert!(setup.assume_yes);
        assert_eq!(
            setup.selected_tools,
            Some(vec![
                SetupTool::Lynis,
                SetupTool::Fail2Ban,
                SetupTool::Trivy
            ])
        );
    }

    #[test]
    fn rejects_unknown_setup_tool() {
        let error = AppConfig::parse([
            String::from("setup"),
            String::from("--tool"),
            String::from("dockle"),
        ])
        .expect_err("unknown setup tool should be rejected");

        assert!(matches!(
            error,
            super::AppError::InvalidArgumentCombination(_)
        ));
    }
}
