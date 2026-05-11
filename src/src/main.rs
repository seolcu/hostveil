use std::os::unix::process::CommandExt;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let bin_args: Vec<String> = args.into_iter().skip(1).collect();

    let exe = std::env::current_exe().unwrap_or_else(|_| "hostveil".into());
    if let Some(mut cmd) = hostveil::app::build_privilege_escalation_cmd(&bin_args, &exe) {
        let err = cmd.exec();
        eprintln!(
            "{}",
            hostveil::i18n::tr_privilege_escalation_failed(&err.to_string())
        );
        return ExitCode::FAILURE;
    }

    let app_args: Vec<String> = bin_args
        .into_iter()
        .filter(|a| a != "--user-mode")
        .collect();

    hostveil::i18n::initialize_locale_from_args(&app_args);

    match hostveil::app::run(app_args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let is_threshold = matches!(error, hostveil::app::AppError::ThresholdExceeded { .. });
            eprintln!("{error}");
            if is_threshold {
                ExitCode::from(1)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}
