mod config;
mod scan;

pub use config::{AppConfig, OutputMode};

use std::fmt;
use std::io;

use crate::compose::ComposeParseError;
use crate::export;
use crate::i18n;
use crate::tui;

#[derive(Debug)]
pub enum AppError {
    UnknownArgument(String),
    MissingArgumentValue(&'static str),
    ComposeParse(ComposeParseError),
    Io(io::Error),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownArgument(argument) => write!(f, "{}", i18n::tr_unknown_argument(argument)),
            Self::MissingArgumentValue(flag) => {
                write!(f, "{}", i18n::tr_missing_argument_value(flag))
            }
            Self::ComposeParse(error) => write!(f, "{}", i18n::tr_compose_parse_error(error)),
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

pub fn run(args: impl IntoIterator<Item = String>) -> Result<(), AppError> {
    let config = AppConfig::parse(args)?;

    if config.show_help {
        print!("{}", i18n::tr("app.help.text"));
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
