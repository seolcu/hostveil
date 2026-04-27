use std::os::unix::process::CommandExt;
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let bin_args: Vec<String> = args.into_iter().skip(1).collect();

    let is_user_mode = bin_args.iter().any(|arg| arg == "--user-mode");
    let is_passive = bin_args
        .iter()
        .any(|arg| arg == "--help" || arg == "-h" || arg == "--version" || arg == "-V");

    if !is_user_mode
        && !is_passive
        && let Ok(output) = Command::new("id").arg("-u").output()
        && let Ok(uid_str) = String::from_utf8(output.stdout)
        && uid_str.trim() != "0"
    {
        let exe = std::env::current_exe().unwrap_or_else(|_| "hostveil".into());
        let mut cmd = Command::new("sudo");
        cmd.arg(exe);
        // Pass HOSTVEIL_LOCALE as an explicit CLI argument so it survives
        // sudo's default env_reset policy.
        let has_locale_flag = bin_args.iter().any(|a| a.starts_with("--locale"));
        if !has_locale_flag && let Ok(hostveil_locale) = std::env::var("HOSTVEIL_LOCALE") {
            cmd.arg("--locale");
            cmd.arg(&hostveil_locale);
        }
        cmd.args(&bin_args);
        let err = cmd.exec();
        eprintln!("Failed to elevate privileges: {err}");
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
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
