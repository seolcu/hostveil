use std::path::PathBuf;

use super::AppError;
use crate::fix::FixMode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    Tui,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ScanAdapter {
    Trivy,
    Dockle,
    Lynis,
}

impl ScanAdapter {
    pub const ALL: [Self; 3] = [Self::Trivy, Self::Dockle, Self::Lynis];

    pub fn from_arg(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "trivy" => Some(Self::Trivy),
            "dockle" => Some(Self::Dockle),
            "lynis" => Some(Self::Lynis),
            _ => None,
        }
    }

    pub fn cli_name(self) -> &'static str {
        match self {
            Self::Trivy => "trivy",
            Self::Dockle => "dockle",
            Self::Lynis => "lynis",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdapterSelection {
    pub trivy: bool,
    pub dockle: bool,
    pub lynis: bool,
}

impl AdapterSelection {
    pub const fn all() -> Self {
        Self {
            trivy: true,
            dockle: true,
            lynis: true,
        }
    }

    pub const fn none() -> Self {
        Self {
            trivy: false,
            dockle: false,
            lynis: false,
        }
    }

    pub const fn is_enabled(self, adapter: ScanAdapter) -> bool {
        match adapter {
            ScanAdapter::Trivy => self.trivy,
            ScanAdapter::Dockle => self.dockle,
            ScanAdapter::Lynis => self.lynis,
        }
    }

    fn enable(&mut self, adapter: ScanAdapter) {
        match adapter {
            ScanAdapter::Trivy => self.trivy = true,
            ScanAdapter::Dockle => self.dockle = true,
            ScanAdapter::Lynis => self.lynis = true,
        }
    }
}

impl Default for AdapterSelection {
    fn default() -> Self {
        Self::all()
    }
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
    pub locale_override: Option<String>,
    pub output_mode: OutputMode,
    pub show_help: bool,
    pub show_version: bool,
    pub lifecycle_command: Option<LifecycleCommand>,
    pub setup_command: Option<SetupConfig>,
    pub compose_path: Option<PathBuf>,
    pub host_root: Option<PathBuf>,
    pub adapter_selection: AdapterSelection,
    pub fix_mode: Option<FixMode>,
    pub fix_target_path: Option<PathBuf>,
    pub preview_changes: bool,
    pub assume_yes: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            locale_override: None,
            output_mode: OutputMode::Tui,
            show_help: false,
            show_version: false,
            lifecycle_command: None,
            setup_command: None,
            compose_path: None,
            host_root: None,
            adapter_selection: AdapterSelection::all(),
            fix_mode: None,
            fix_target_path: None,
            preview_changes: false,
            assume_yes: false,
        }
    }
}

impl AppConfig {
    pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, AppError> {
        let adapter_env = std::env::var("HOSTVEIL_ADAPTERS").ok();
        Self::parse_with_adapter_env(args, adapter_env.as_deref())
    }

    fn parse_with_adapter_env(
        args: impl IntoIterator<Item = String>,
        adapter_env: Option<&str>,
    ) -> Result<Self, AppError> {
        let args: Vec<String> = args.into_iter().collect();
        let (locale_override, args) = strip_locale_override(args)?;

        if let Some(command) = args.first() {
            match command.as_str() {
                "setup" => {
                    let mut config = Self::parse_setup(args.into_iter().skip(1))?;
                    config.locale_override = locale_override;
                    return Ok(config);
                }
                "upgrade" => {
                    let mut config = Self::parse_upgrade(args.into_iter().skip(1))?;
                    config.locale_override = locale_override;
                    return Ok(config);
                }
                "uninstall" => {
                    let mut config = Self::parse_uninstall(args.into_iter().skip(1))?;
                    config.locale_override = locale_override;
                    return Ok(config);
                }
                "auto-upgrade" => {
                    let mut config = Self::parse_auto_upgrade(args.into_iter().skip(1))?;
                    config.locale_override = locale_override;
                    return Ok(config);
                }
                _ => {}
            }
        }

        let mut config = Self {
            locale_override,
            ..Self::default()
        };
        let mut adapter_selection_explicit = false;
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
                "--adapters" => {
                    let value = args
                        .next()
                        .ok_or(AppError::MissingArgumentValue("--adapters"))?;
                    config.adapter_selection = parse_adapter_selection(&value)?;
                    adapter_selection_explicit = true;
                }
                _ if argument.starts_with("--adapters=") => {
                    let value = argument.trim_start_matches("--adapters=");
                    if value.is_empty() {
                        return Err(AppError::MissingArgumentValue("--adapters"));
                    }
                    config.adapter_selection = parse_adapter_selection(value)?;
                    adapter_selection_explicit = true;
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

        if !adapter_selection_explicit
            && config.fix_mode.is_none()
            && let Some(adapter_env) = adapter_env
        {
            config.adapter_selection = parse_adapter_selection(adapter_env)?;
        }

        if config.fix_mode.is_some() && adapter_selection_explicit {
            return Err(AppError::InvalidArgumentCombination(
                crate::i18n::tr_adapters_require_scan_mode(),
            ));
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

        for argument in args {
            match argument.as_str() {
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
            return Err(AppError::InvalidArgumentCombination(
                crate::i18n::tr_auto_upgrade_mode_required(),
            ));
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
                return Err(AppError::InvalidArgumentCombination(
                    crate::i18n::tr_auto_upgrade_mode_required(),
                ));
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
                return Err(AppError::InvalidArgumentCombination(
                    crate::i18n::tr_fix_requires_target(),
                ));
            }
            if self.host_root.is_some() {
                return Err(AppError::InvalidArgumentCombination(
                    crate::i18n::tr_fix_host_root_not_supported(),
                ));
            }
            if self.compose_path.is_some() {
                return Err(AppError::InvalidArgumentCombination(
                    crate::i18n::tr_fix_compose_conflict(),
                ));
            }
            if self.output_mode == OutputMode::Json {
                return Err(AppError::InvalidArgumentCombination(
                    crate::i18n::tr_fix_json_not_supported(),
                ));
            }
        } else if self.preview_changes || self.assume_yes {
            return Err(AppError::InvalidArgumentCombination(
                crate::i18n::tr_preview_yes_requires_fix_mode(),
            ));
        }

        Ok(())
    }

    fn set_fix_target(&mut self, mode: FixMode, path: PathBuf) -> Result<(), AppError> {
        if self.fix_mode.is_some() {
            return Err(AppError::InvalidArgumentCombination(
                crate::i18n::tr_fix_mode_conflict(),
            ));
        }

        self.fix_mode = Some(mode);
        self.fix_target_path = Some(path);
        Ok(())
    }
}

fn strip_locale_override(args: Vec<String>) -> Result<(Option<String>, Vec<String>), AppError> {
    let mut locale_override = None;
    let mut stripped = Vec::new();
    let mut args = args.into_iter();

    while let Some(argument) = args.next() {
        let locale_value = match argument.as_str() {
            "--locale" => Some(
                args.next()
                    .ok_or(AppError::MissingArgumentValue("--locale"))?,
            ),
            _ if argument.starts_with("--locale=") => {
                let value = argument.trim_start_matches("--locale=");
                if value.is_empty() {
                    return Err(AppError::MissingArgumentValue("--locale"));
                }
                Some(String::from(value))
            }
            _ => None,
        };

        if let Some(value) = locale_value {
            let normalized = crate::i18n::parse_supported_locale(&value).ok_or_else(|| {
                AppError::InvalidArgumentCombination(crate::i18n::tr_unsupported_locale(&value))
            })?;

            if locale_override.replace(String::from(normalized)).is_some() {
                return Err(AppError::InvalidArgumentCombination(
                    crate::i18n::tr_duplicate_locale_override(),
                ));
            }
        } else {
            stripped.push(argument);
        }
    }

    Ok((locale_override, stripped))
}

fn push_setup_tool(tools: &mut Vec<SetupTool>, value: &str) -> Result<(), AppError> {
    let tool = SetupTool::from_arg(value).ok_or_else(|| {
        AppError::InvalidArgumentCombination(crate::i18n::tr_unsupported_setup_tool(value))
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
        Err(AppError::InvalidArgumentCombination(
            crate::i18n::tr_setup_tools_required(),
        ))
    }
}

fn parse_adapter_selection(value: &str) -> Result<AdapterSelection, AppError> {
    let entries: Vec<String> = value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| entry.to_ascii_lowercase())
        .collect();

    if entries.is_empty() {
        return Err(AppError::InvalidArgumentCombination(
            crate::i18n::tr_adapter_selection_required(),
        ));
    }

    let has_all = entries.iter().any(|entry| entry == "all");
    let has_none = entries.iter().any(|entry| entry == "none");

    if (has_all || has_none) && entries.len() > 1 {
        return Err(AppError::InvalidArgumentCombination(
            crate::i18n::tr_adapter_selection_keyword_conflict(),
        ));
    }

    if has_all {
        return Ok(AdapterSelection::all());
    }

    if has_none {
        return Ok(AdapterSelection::none());
    }

    let mut selection = AdapterSelection::none();
    for entry in entries {
        let adapter = ScanAdapter::from_arg(&entry).ok_or_else(|| {
            AppError::InvalidArgumentCombination(crate::i18n::tr_unsupported_adapter(&entry))
        })?;
        selection.enable(adapter);
    }

    Ok(selection)
}

#[cfg(test)]
mod tests {
    use super::{AdapterSelection, AppConfig, LifecycleCommand, OutputMode, SetupTool};
    use crate::fix::FixMode;

    #[test]
    fn defaults_to_tui_mode() {
        let config = AppConfig::parse(Vec::<String>::new()).expect("config should parse");

        assert_eq!(config.output_mode, OutputMode::Tui);
        assert!(!config.show_help);
        assert!(!config.show_version);
        assert!(config.lifecycle_command.is_none());
        assert!(config.setup_command.is_none());
        assert_eq!(config.adapter_selection, AdapterSelection::all());
        assert!(config.fix_mode.is_none());
    }

    #[test]
    fn parses_json_flag() {
        let config = AppConfig::parse([String::from("--json")]).expect("config should parse");

        assert_eq!(config.output_mode, OutputMode::Json);
    }

    #[test]
    fn parses_global_locale_override() {
        let config = AppConfig::parse([
            String::from("--locale"),
            String::from("ko_KR.UTF-8"),
            String::from("--json"),
        ])
        .expect("config should parse");

        assert_eq!(config.locale_override.as_deref(), Some("ko"));
    }

    #[test]
    fn parses_locale_override_before_subcommand() {
        let config = AppConfig::parse([
            String::from("--locale=en"),
            String::from("setup"),
            String::from("--yes"),
        ])
        .expect("config should parse");

        assert_eq!(config.locale_override.as_deref(), Some("en"));
        assert!(config.setup_command.is_some());
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
        let config = AppConfig::parse([String::from("upgrade")])
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

    #[test]
    fn parses_adapter_selection_all() {
        let config =
            AppConfig::parse([String::from("--adapters=all")]).expect("config should parse");

        assert_eq!(config.adapter_selection, AdapterSelection::all());
    }

    #[test]
    fn parses_adapter_selection_none() {
        let config =
            AppConfig::parse([String::from("--adapters=none")]).expect("config should parse");

        assert_eq!(config.adapter_selection, AdapterSelection::none());
    }

    #[test]
    fn parses_adapter_selection_list() {
        let config = AppConfig::parse([
            String::from("--adapters"),
            String::from("trivy,dockle"),
            String::from("--json"),
        ])
        .expect("config should parse");

        assert!(config.adapter_selection.trivy);
        assert!(config.adapter_selection.dockle);
        assert!(!config.adapter_selection.lynis);
    }

    #[test]
    fn adapter_selection_uses_env_fallback() {
        let config = AppConfig::parse_with_adapter_env([String::from("--json")], Some("lynis"))
            .expect("config should parse");

        assert!(!config.adapter_selection.trivy);
        assert!(!config.adapter_selection.dockle);
        assert!(config.adapter_selection.lynis);
    }

    #[test]
    fn adapter_selection_cli_overrides_env() {
        let config = AppConfig::parse_with_adapter_env(
            [String::from("--adapters=trivy"), String::from("--json")],
            Some("none"),
        )
        .expect("config should parse");

        assert!(config.adapter_selection.trivy);
        assert!(!config.adapter_selection.dockle);
        assert!(!config.adapter_selection.lynis);
    }

    #[test]
    fn rejects_unknown_adapter_selection() {
        let error = AppConfig::parse([String::from("--adapters=nmap")])
            .expect_err("unknown adapter should be rejected");

        assert!(matches!(
            error,
            super::AppError::InvalidArgumentCombination(_)
        ));
    }

    #[test]
    fn rejects_none_combined_with_adapter_selection() {
        let error = AppConfig::parse([String::from("--adapters=none,trivy")])
            .expect_err("none should be exclusive");

        assert!(matches!(
            error,
            super::AppError::InvalidArgumentCombination(_)
        ));
    }

    #[test]
    fn rejects_adapters_with_fix_mode() {
        let error = AppConfig::parse([
            String::from("--quick-fix"),
            String::from("docker-compose.yml"),
            String::from("--adapters=none"),
        ])
        .expect_err("adapter selection should require scan mode");

        assert!(matches!(
            error,
            super::AppError::InvalidArgumentCombination(_)
        ));
    }

    #[test]
    fn rejects_duplicate_locale_override() {
        let error = AppConfig::parse([
            String::from("--locale=en"),
            String::from("--locale"),
            String::from("ko"),
        ])
        .expect_err("duplicate locale overrides should be rejected");

        assert!(matches!(
            error,
            super::AppError::InvalidArgumentCombination(_)
        ));
    }

    #[test]
    fn duplicate_locale_override_uses_translation_helper_detail() {
        let error = AppConfig::parse([
            String::from("--locale=en"),
            String::from("--locale"),
            String::from("ko"),
        ])
        .expect_err("duplicate locale overrides should be rejected");

        assert!(matches!(
            error,
            super::AppError::InvalidArgumentCombination(message)
                if message == crate::i18n::tr_duplicate_locale_override()
        ));
    }
}
