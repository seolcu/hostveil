use std::process::ExitCode;

fn main() -> ExitCode {
    hostveil::i18n::initialize_locale_from_env();

    match hostveil::app::run(std::env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
