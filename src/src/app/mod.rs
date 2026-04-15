mod config;
mod scan;
mod setup;

pub use config::{AppConfig, OutputMode, SetupConfig, SetupTool};

use std::fmt;
use std::io::{self, Write};

#[cfg(not(test))]
use std::io::IsTerminal;

use crate::compose::ComposeParseError;
use crate::export;
use crate::fix::{self, FixError};
use crate::i18n;
use crate::tui;

#[derive(Debug)]
pub enum AppError {
    UnknownArgument(String),
    MissingArgumentValue(&'static str),
    InvalidArgumentCombination(String),
    LifecycleCommandRequiresInstalledWrapper(&'static str),
    TuiRequiresTerminal,
    FixRequiresTerminal,
    ComposeParse(ComposeParseError),
    Fix(FixError),
    Io(io::Error),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownArgument(argument) => write!(f, "{}", i18n::tr_unknown_argument(argument)),
            Self::MissingArgumentValue(flag) => {
                write!(f, "{}", i18n::tr_missing_argument_value(flag))
            }
            Self::InvalidArgumentCombination(message) => {
                write!(f, "{}", i18n::tr_invalid_argument_combination(message))
            }
            Self::LifecycleCommandRequiresInstalledWrapper(command) => write!(
                f,
                "{}",
                i18n::tr_lifecycle_command_requires_installed_wrapper(command)
            ),
            Self::TuiRequiresTerminal => write!(f, "{}", i18n::tr_tui_requires_terminal()),
            Self::FixRequiresTerminal => write!(f, "{}", i18n::tr_fix_requires_terminal()),
            Self::ComposeParse(error) => write!(f, "{}", i18n::tr_compose_parse_error(error)),
            Self::Fix(error) => write!(f, "{error}"),
            Self::Io(error) => write!(f, "{}", i18n::tr_io_error(&error.to_string())),
        }
    }
}

impl std::error::Error for AppError {}

impl From<ComposeParseError> for AppError {
    fn from(value: ComposeParseError) -> Self {
        Self::ComposeParse(value)
    }
}

impl From<io::Error> for AppError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<FixError> for AppError {
    fn from(value: FixError) -> Self {
        Self::Fix(value)
    }
}

pub fn run(args: impl IntoIterator<Item = String>) -> Result<(), AppError> {
    let config = AppConfig::parse(args)?;

    if config.show_help {
        print!("{}", i18n::tr("app.help.text"));
        return Ok(());
    }

    if config.show_version {
        println!(
            "{}",
            i18n::tr_version(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
        );
        return Ok(());
    }

    if let Some(setup_config) = config.setup_command.as_ref() {
        return setup::run(setup_config);
    }

    if let Some(command) = config.lifecycle_command {
        return Err(AppError::LifecycleCommandRequiresInstalledWrapper(
            command.name(),
        ));
    }

    if let Some(mode) = config.fix_mode {
        let compose_path = config.fix_target_path.as_ref().ok_or_else(|| {
            AppError::InvalidArgumentCombination(String::from(
                "a compose target is required for fix operations",
            ))
        })?;

        let preview_plan = fix::preview(compose_path, mode)?;
        if config.preview_changes {
            print_fix_review(&preview_plan);
            println!();
            print!("{}", t!("app.fix.preview_only").into_owned());
            return Ok(());
        }

        if !preview_plan.changed() {
            print_fix_review(&preview_plan);
            return Ok(());
        }

        if mode == crate::fix::FixMode::Fix {
            if config.assume_yes {
                print_fix_review(&preview_plan);
            } else {
                if !is_interactive_terminal() {
                    return Err(AppError::FixRequiresTerminal);
                }

                let confirmed = tui::run_fix_review(&preview_plan)?;
                if !confirmed {
                    print!("{}", t!("app.fix.cancelled").into_owned());
                    return Ok(());
                }
            }
        } else {
            print_fix_review(&preview_plan);

            if !config.assume_yes && !confirm_fix(compose_path, mode)? {
                print!("{}", t!("app.fix.cancelled").into_owned());
                return Ok(());
            }
        }

        let applied_plan = fix::apply(compose_path, mode)?;
        print_fix_result(&applied_plan);
        return Ok(());
    }

    match config.output_mode {
        OutputMode::Tui => {
            if !is_interactive_terminal() {
                return Err(AppError::TuiRequiresTerminal);
            }

            let mut scan_result = scan::run_native(&config)?;
            let adapter_updates = scan::prepare_background_adapter_scan(&mut scan_result);

            tui::run(&mut scan_result, move |scan_result| {
                let mut updated = false;

                while let Ok(update) = adapter_updates.try_recv() {
                    scan::apply_external_adapter_update(scan_result, update);
                    updated = true;
                }

                updated
            })?;
        }
        OutputMode::Json => {
            let scan_result = scan::run(&config)?;
            print!("{}", export::scan_result_json(&scan_result));
        }
    }

    Ok(())
}

fn is_interactive_terminal() -> bool {
    #[cfg(test)]
    {
        false
    }

    #[cfg(not(test))]
    {
        io::stdin().is_terminal() && io::stdout().is_terminal()
    }
}

fn confirm_fix(
    compose_path: &std::path::Path,
    mode: crate::fix::FixMode,
) -> Result<bool, AppError> {
    let prompt = match mode {
        crate::fix::FixMode::QuickFix => t!(
            "app.fix.confirm_quick",
            path = compose_path.display().to_string()
        )
        .into_owned(),
        crate::fix::FixMode::Fix => t!(
            "app.fix.confirm_all",
            path = compose_path.display().to_string()
        )
        .into_owned(),
    };

    print!("{prompt}");
    io::stdout().flush()?;

    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn print_fix_review(plan: &fix::FixPlan) {
    println!(
        "{}",
        t!(
            "app.fix.file",
            path = plan.compose_file.display().to_string()
        )
        .into_owned()
    );

    if !plan.safe_applied.is_empty() {
        println!(
            "{}",
            t!("app.fix.safe_plan", count = plan.safe_applied.len()).into_owned()
        );
    }
    if !plan.guided_applied.is_empty() {
        println!(
            "{}",
            t!("app.fix.guided_plan", count = plan.guided_applied.len()).into_owned()
        );
    }

    if plan.changed() {
        println!();
        print!("{}", plan.diff_preview);
    } else {
        println!("{}", t!("app.fix.none").into_owned());
    }
}

fn print_fix_result(plan: &fix::FixPlan) {
    if let Some(backup_path) = &plan.backup_path {
        println!();
        println!(
            "{}",
            t!("app.fix.backup", path = backup_path.display().to_string()).into_owned()
        );
    }

    for applied in &plan.safe_applied {
        println!(
            "{}",
            t!("app.fix.applied", summary = applied.summary.as_str()).into_owned()
        );
    }
    for applied in &plan.guided_applied {
        println!(
            "{}",
            t!("app.fix.applied", summary = applied.summary.as_str()).into_owned()
        );
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{AppError, run};

    fn temp_compose_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should move forward")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "hostveil-app-{name}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("temp dir should exist");
        path
    }

    fn write_compose(path: &Path, content: &str) {
        fs::write(path, content).expect("compose file should be written");
    }

    #[test]
    fn fix_requires_terminal_without_yes() {
        let root = temp_compose_dir("fix-terminal");
        let path = root.join("docker-compose.yml");
        write_compose(
            &path,
            concat!(
                "services:\n",
                "  app:\n",
                "    image: alpine:3.20\n",
                "    privileged: true\n",
                "    ports:\n",
                "      - \"127.0.0.1:8080:80\"\n"
            ),
        );

        let error = run([String::from("--fix"), path.display().to_string()])
            .expect_err("non-interactive guided fix should require terminal review");

        assert!(matches!(error, AppError::FixRequiresTerminal));

        fs::remove_dir_all(root).expect("temp dir should be removed");
    }

    #[test]
    fn fix_with_yes_applies_guided_changes_without_terminal() {
        let root = temp_compose_dir("fix-yes");
        let path = root.join("docker-compose.yml");
        write_compose(
            &path,
            concat!(
                "services:\n",
                "  app:\n",
                "    image: alpine:3.20\n",
                "    privileged: true\n",
                "    ports:\n",
                "      - \"127.0.0.1:8080:80\"\n"
            ),
        );

        run([
            String::from("--fix"),
            path.display().to_string(),
            String::from("--yes"),
        ])
        .expect("guided fix should apply without interactive review when --yes is set");

        let updated = fs::read_to_string(&path).expect("compose file should be readable");
        assert!(path.with_extension("yml.bak").exists());
        assert!(updated.contains("NET_BIND_SERVICE"));
        assert!(!updated.contains("privileged: true"));

        fs::remove_dir_all(root).expect("temp dir should be removed");
    }

    #[test]
    fn installed_lifecycle_command_requires_wrapper_context() {
        let error = run([String::from("upgrade")])
            .expect_err("direct binary lifecycle commands should fail clearly");

        assert!(matches!(
            error,
            AppError::LifecycleCommandRequiresInstalledWrapper("upgrade")
        ));
    }
}
