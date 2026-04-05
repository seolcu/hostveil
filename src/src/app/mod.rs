mod config;
mod scan;

pub use config::{AppConfig, OutputMode};

use std::fmt;
use std::io::{self, Write};

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

    if let Some(mode) = config.fix_mode {
        let compose_path = config.fix_target_path.as_ref().ok_or_else(|| {
            AppError::InvalidArgumentCombination(String::from(
                "a compose target is required for fix operations",
            ))
        })?;

        let preview_plan = fix::preview(compose_path, mode)?;
        print_fix_review(&preview_plan);

        if config.preview_changes {
            println!();
            print!("{}", t!("app.fix.preview_only").into_owned());
            return Ok(());
        }

        if !preview_plan.changed() {
            return Ok(());
        }

        if !config.assume_yes && !confirm_fix(compose_path, mode)? {
            print!("{}", t!("app.fix.cancelled").into_owned());
            return Ok(());
        }

        let applied_plan = fix::apply(compose_path, mode)?;
        print_fix_result(&applied_plan);
        return Ok(());
    }

    let scan_result = scan::run(&config)?;

    match config.output_mode {
        OutputMode::Tui => tui::run(&scan_result)?,
        OutputMode::Json => {
            print!("{}", export::scan_result_json(&scan_result));
        }
    }

    Ok(())
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
