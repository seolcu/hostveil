mod config;
pub(crate) mod scan;
mod setup;

pub use config::{AdapterSelection, AppConfig, OutputMode, ScanAdapter, SetupConfig, SetupTool};

use std::env;
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
    LifecycleCommandRequiresPackageManager {
        command: &'static str,
        install_kind: PackageInstallKind,
    },
    TuiRequiresTerminal,
    FixRequiresTerminal,
    ComposeParse(ComposeParseError),
    Fix(FixError),
    Io(io::Error),
    ThresholdExceeded {
        threshold: String,
        count: usize,
    },
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
            Self::LifecycleCommandRequiresPackageManager {
                command,
                install_kind,
            } => write!(
                f,
                "{}",
                i18n::tr_lifecycle_command_requires_package_manager(command, install_kind.as_key())
            ),
            Self::TuiRequiresTerminal => write!(f, "{}", i18n::tr_tui_requires_terminal()),
            Self::FixRequiresTerminal => write!(f, "{}", i18n::tr_fix_requires_terminal()),
            Self::ComposeParse(error) => write!(f, "{}", i18n::tr_compose_parse_error(error)),
            Self::Fix(error) => write!(f, "{error}"),
            Self::Io(error) => write!(f, "{}", i18n::tr_io_error(&error.to_string())),
            Self::ThresholdExceeded { threshold, count } => write!(
                f,
                "{}",
                i18n::tr("app.fail_on.exceeded")
                    .replace("%{threshold}", threshold)
                    .replace("%{count}", &count.to_string())
            ),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageInstallKind {
    Deb,
    Rpm,
}

impl PackageInstallKind {
    fn from_env() -> Option<Self> {
        match env::var("HOSTVEIL_PACKAGE_INSTALL_KIND").ok()?.as_str() {
            "deb" => Some(Self::Deb),
            "rpm" => Some(Self::Rpm),
            _ => None,
        }
    }

    fn as_key(self) -> &'static str {
        match self {
            Self::Deb => "deb",
            Self::Rpm => "rpm",
        }
    }
}

pub fn run(args: impl IntoIterator<Item = String>) -> Result<(), AppError> {
    let config = AppConfig::parse(args)?;
    crate::i18n::initialize_locale(config.locale_override.as_deref());

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
        if let Some(install_kind) = PackageInstallKind::from_env() {
            return Err(AppError::LifecycleCommandRequiresPackageManager {
                command: command.name(),
                install_kind,
            });
        }
        return Err(AppError::LifecycleCommandRequiresInstalledWrapper(
            command.name(),
        ));
    }

    if config.quick_fix_alias_used {
        eprintln!("{}", t!("app.warning.quick_fix_deprecated").into_owned());
    }

    if let Some(mode) = config.fix_mode {
        let compose_path = config.fix_target_path.as_ref().ok_or_else(|| {
            AppError::InvalidArgumentCombination(crate::i18n::tr_fix_requires_target())
        })?;

        let preview_plan = match fix::preview(compose_path, mode, None) {
            Ok(plan) => plan,
            Err(FixError::ReviewRequired(_))
                if mode == crate::fix::FixMode::Fix && config.assume_yes =>
            {
                return Err(AppError::InvalidArgumentCombination(
                    t!("app.validation.review_required_for_fix_yes").into_owned(),
                ));
            }
            Err(FixError::ReviewRequired(_)) if mode == crate::fix::FixMode::Fix => {
                if !is_interactive_terminal() {
                    return Err(AppError::FixRequiresTerminal);
                }
                let Some(result) = tui::run_interactive_fix_flow(
                    compose_path,
                    mode,
                    None,
                    &[],
                    !config.preview_changes,
                )?
                else {
                    print!("{}", t!("app.fix.cancelled").into_owned());
                    return Ok(());
                };

                if config.preview_changes {
                    print_fix_review(&result.plan);
                    println!();
                    print!("{}", t!("app.fix.preview_only").into_owned());
                    return Ok(());
                }

                let applied_plan =
                    fix::apply_with_resolutions(compose_path, mode, None, &result.resolutions)?;
                print_fix_result(&applied_plan);
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
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

        let applied_plan = fix::apply(compose_path, mode, None)?;
        print_fix_result(&applied_plan);
        return Ok(());
    }

    match config.output_mode {
        OutputMode::Tui => {
            if !is_interactive_terminal() {
                return Err(AppError::TuiRequiresTerminal);
            }

            loop {
                let mut scan_result = scan::run_native(&config)?;
                let adapter_updates = scan::prepare_background_adapter_scan(
                    &mut scan_result,
                    config.adapter_selection,
                    config
                        .adapter_timeout
                        .unwrap_or(crate::adapters::command::DEFAULT_ADAPTER_TIMEOUT),
                );

                let action = tui::run(&mut scan_result, move |scan_result| {
                    let mut updated = false;

                    while let Ok(event) = adapter_updates.try_recv() {
                        scan::apply_external_adapter_event(scan_result, event);
                        updated = true;
                    }

                    updated
                })?;

                match action {
                    tui::TuiAction::Exit => break,
                    tui::TuiAction::TriggerFix {
                        compose_file,
                        finding_id,
                        adapter_findings,
                    } => {
                        let filter = finding_id.map(|id| vec![id]);
                        let filter_slice = filter.as_deref();
                        let Some(result) = tui::run_interactive_fix_flow(
                            &compose_file,
                            crate::fix::FixMode::Fix,
                            filter_slice,
                            &adapter_findings,
                            true,
                        )?
                        else {
                            eprintln!("{}", t!("app.fix.cancelled").into_owned());
                            continue;
                        };

                        if result.plan.changed() {
                            fix::apply_with_external(
                                &compose_file,
                                crate::fix::FixMode::Fix,
                                filter_slice,
                                &adapter_findings,
                                &result.resolutions,
                            )?;
                        } else {
                            eprintln!("{}", t!("app.fix.none").into_owned());
                        }
                    }
                }
            }
        }
        OutputMode::Json => {
            let scan_result = scan::run(&config)?;
            print!(
                "{}",
                export::scan_result_json_filtered(&scan_result, config.findings_only)
            );
            if let Some(error) = check_threshold(&scan_result, config.fail_on) {
                return Err(error);
            }
        }
        OutputMode::Sarif => {
            let scan_result = scan::run(&config)?;
            print!("{}", export::scan_result_sarif(&scan_result));
            if let Some(error) = check_threshold(&scan_result, config.fail_on) {
                return Err(error);
            }
        }
        OutputMode::Markdown => {
            let scan_result = scan::run(&config)?;
            print!("{}", export::scan_result_markdown(&scan_result));
            if let Some(error) = check_threshold(&scan_result, config.fail_on) {
                return Err(error);
            }
        }
        OutputMode::Html => {
            let scan_result = scan::run(&config)?;
            print!("{}", export::scan_result_html(&scan_result));
            if let Some(error) = check_threshold(&scan_result, config.fail_on) {
                return Err(error);
            }
        }
    }

    Ok(())
}

fn check_threshold(
    scan_result: &crate::domain::ScanResult,
    fail_on: Option<crate::domain::Severity>,
) -> Option<AppError> {
    let threshold = fail_on?;
    let count = scan_result
        .findings
        .iter()
        .filter(|f| severity_meets_threshold(f.severity, threshold))
        .count();
    if count > 0 {
        Some(AppError::ThresholdExceeded {
            threshold: threshold.as_key().to_owned(),
            count,
        })
    } else {
        None
    }
}

fn severity_meets_threshold(
    severity: crate::domain::Severity,
    threshold: crate::domain::Severity,
) -> bool {
    use crate::domain::Severity;
    match threshold {
        Severity::Critical => severity == Severity::Critical,
        Severity::High => matches!(severity, Severity::Critical | Severity::High),
        Severity::Medium => matches!(
            severity,
            Severity::Critical | Severity::High | Severity::Medium
        ),
        Severity::Low => true,
    }
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
        crate::fix::FixMode::AutoFix => t!(
            "app.fix.confirm_auto",
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

    if !plan.auto_applied.is_empty() {
        println!(
            "{}",
            t!("app.fix.auto_plan", count = plan.auto_applied.len()).into_owned()
        );
    }
    if !plan.review_applied.is_empty() {
        println!(
            "{}",
            t!("app.fix.review_plan", count = plan.review_applied.len()).into_owned()
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

    for applied in &plan.auto_applied {
        println!(
            "{}",
            t!("app.fix.applied", summary = applied.summary.as_str()).into_owned()
        );
    }
    for applied in &plan.review_applied {
        println!(
            "{}",
            t!("app.fix.applied", summary = applied.summary.as_str()).into_owned()
        );
    }
}

/// Check if privilege escalation is needed and build the sudo command.
/// Returns `None` if no escalation is needed (already root, passive mode, or user mode).
#[cfg(unix)]
pub fn build_privilege_escalation_cmd(
    bin_args: &[String],
    current_exe: &std::path::Path,
) -> Option<std::process::Command> {
    let is_user_mode = bin_args.iter().any(|arg| arg == "--user-mode");
    let is_lifecycle = matches!(
        bin_args.first().map(String::as_str),
        Some("upgrade" | "uninstall" | "auto-upgrade")
    );
    let is_passive = bin_args
        .iter()
        .any(|arg| arg == "--help" || arg == "-h" || arg == "--version" || arg == "-V")
        || is_lifecycle;

    if is_user_mode || is_passive {
        return None;
    }

    let uid = std::process::Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|s| s.trim().to_owned())?;

    if uid == "0" {
        return None;
    }

    let mut cmd = std::process::Command::new("sudo");
    cmd.arg(current_exe);

    let has_locale_flag = bin_args.iter().any(|a| a.starts_with("--locale"));
    if !has_locale_flag && let Ok(hostveil_locale) = std::env::var("HOSTVEIL_LOCALE") {
        cmd.arg("--locale");
        cmd.arg(&hostveil_locale);
    }

    cmd.args(bin_args);
    Some(cmd)
}

#[cfg(not(unix))]
pub fn build_privilege_escalation_cmd(
    _bin_args: &[String],
    _current_exe: &std::path::Path,
) -> Option<std::process::Command> {
    None
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{AppError, PackageInstallKind, build_privilege_escalation_cmd, run};

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

    fn package_mode_env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
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
            .expect_err("non-interactive fix should require terminal review");

        assert!(matches!(error, AppError::FixRequiresTerminal));

        fs::remove_dir_all(root).expect("temp dir should be removed");
    }

    #[test]
    fn auto_fix_with_yes_applies_auto_changes_without_terminal() {
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
            String::from("--auto-fix"),
            path.display().to_string(),
            String::from("--yes"),
        ])
        .expect("auto fix should apply without interactive review when --yes is set");

        let updated = fs::read_to_string(&path).expect("compose file should be readable");
        let backup_exists = fs::read_dir(&root)
            .expect("root dir should be readable")
            .filter_map(|entry| entry.ok())
            .any(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.contains(".bak."))
            });
        assert!(backup_exists, "timestamped backup should exist");
        assert!(updated.contains("NET_BIND_SERVICE"));
        assert!(!updated.contains("privileged: true"));

        fs::remove_dir_all(root).expect("temp dir should be removed");
    }

    #[test]
    fn fix_with_yes_rejects_review_required_changes() {
        let root = temp_compose_dir("fix-yes-review");
        let path = root.join("docker-compose.yml");
        write_compose(
            &path,
            concat!("services:\n", "  postgres:\n", "    image: postgres\n"),
        );

        let error = run([
            String::from("--fix"),
            path.display().to_string(),
            String::from("--yes"),
        ])
        .expect_err("review-required fix should fail with --yes");

        assert!(matches!(error, AppError::InvalidArgumentCombination(_)));

        fs::remove_dir_all(root).expect("temp dir should be removed");
    }

    #[test]
    fn installed_lifecycle_command_requires_wrapper_context() {
        let _guard = package_mode_env_lock()
            .lock()
            .expect("package mode env lock should be available");
        unsafe {
            std::env::remove_var("HOSTVEIL_PACKAGE_INSTALL_KIND");
        }

        let error = run([String::from("--locale=en"), String::from("upgrade")])
            .expect_err("direct binary lifecycle commands should fail clearly");

        assert!(matches!(
            error,
            AppError::LifecycleCommandRequiresInstalledWrapper("upgrade")
        ));

        let rendered = error.to_string();
        assert!(rendered.contains("installed hostveil wrapper"));
        assert!(rendered.contains("hostveil upgrade"));
        assert!(rendered.contains("install.sh"));
    }

    #[test]
    fn uninstall_lifecycle_command_requires_wrapper_context() {
        let _guard = package_mode_env_lock()
            .lock()
            .expect("package mode env lock should be available");
        unsafe {
            std::env::remove_var("HOSTVEIL_PACKAGE_INSTALL_KIND");
        }

        let error = run([String::from("--locale=en"), String::from("uninstall")])
            .expect_err("direct binary uninstall should fail clearly");

        assert!(matches!(
            error,
            AppError::LifecycleCommandRequiresInstalledWrapper("uninstall")
        ));

        let rendered = error.to_string();
        assert!(rendered.contains("installed hostveil wrapper"));
        assert!(rendered.contains("hostveil uninstall"));
    }

    #[test]
    fn auto_upgrade_lifecycle_command_requires_wrapper_context() {
        let _guard = package_mode_env_lock()
            .lock()
            .expect("package mode env lock should be available");
        unsafe {
            std::env::remove_var("HOSTVEIL_PACKAGE_INSTALL_KIND");
        }

        let error = run([
            String::from("--locale=en"),
            String::from("auto-upgrade"),
            String::from("disable"),
        ])
        .expect_err("direct binary auto-upgrade should fail clearly");

        assert!(matches!(
            error,
            AppError::LifecycleCommandRequiresInstalledWrapper("auto-upgrade")
        ));

        let rendered = error.to_string();
        assert!(rendered.contains("installed hostveil wrapper"));
        assert!(rendered.contains("hostveil auto-upgrade"));
    }

    #[test]
    fn package_install_upgrade_uses_package_guidance_for_deb() {
        let _guard = package_mode_env_lock()
            .lock()
            .expect("package mode env lock should be available");
        unsafe {
            std::env::set_var("HOSTVEIL_PACKAGE_INSTALL_KIND", "deb");
        }

        let error = run([String::from("--locale=en"), String::from("upgrade")])
            .expect_err("package installs should return package-specific upgrade guidance");

        assert!(matches!(
            error,
            AppError::LifecycleCommandRequiresPackageManager {
                command: "upgrade",
                install_kind: PackageInstallKind::Deb
            }
        ));

        let rendered = error.to_string();
        assert!(rendered.contains("Debian package"));
        assert!(rendered.contains("sudo apt install ./hostveil_<version>_amd64.deb"));

        unsafe {
            std::env::remove_var("HOSTVEIL_PACKAGE_INSTALL_KIND");
        }
    }

    #[test]
    fn package_install_uninstall_uses_package_guidance_for_rpm() {
        let _guard = package_mode_env_lock()
            .lock()
            .expect("package mode env lock should be available");
        unsafe {
            std::env::set_var("HOSTVEIL_PACKAGE_INSTALL_KIND", "rpm");
        }

        let error = run([String::from("--locale=en"), String::from("uninstall")])
            .expect_err("package installs should return package-specific uninstall guidance");

        assert!(matches!(
            error,
            AppError::LifecycleCommandRequiresPackageManager {
                command: "uninstall",
                install_kind: PackageInstallKind::Rpm
            }
        ));

        let rendered = error.to_string();
        assert!(rendered.contains("RPM package"));
        assert!(rendered.contains("sudo dnf remove hostveil"));

        unsafe {
            std::env::remove_var("HOSTVEIL_PACKAGE_INSTALL_KIND");
        }
    }

    #[test]
    fn package_install_auto_upgrade_reports_package_lifecycle_limit() {
        let _guard = package_mode_env_lock()
            .lock()
            .expect("package mode env lock should be available");
        unsafe {
            std::env::set_var("HOSTVEIL_PACKAGE_INSTALL_KIND", "deb");
        }

        let error = run([
            String::from("--locale=en"),
            String::from("auto-upgrade"),
            String::from("disable"),
        ])
        .expect_err("package installs should reject launch-time auto-upgrade");

        assert!(matches!(
            error,
            AppError::LifecycleCommandRequiresPackageManager {
                command: "auto-upgrade",
                install_kind: PackageInstallKind::Deb
            }
        ));

        let rendered = error.to_string();
        assert!(rendered.contains("do not support launch-time auto-upgrade"));
        assert!(rendered.contains("GitHub Releases"));

        unsafe {
            std::env::remove_var("HOSTVEIL_PACKAGE_INSTALL_KIND");
        }
    }

    #[test]
    fn privilege_escalation_skips_user_mode() {
        let cmd = build_privilege_escalation_cmd(
            &[String::from("--user-mode")],
            std::path::Path::new("/bin/hostveil"),
        );
        assert!(cmd.is_none());
    }

    #[test]
    fn privilege_escalation_skips_help() {
        let cmd = build_privilege_escalation_cmd(
            &[String::from("--help")],
            std::path::Path::new("/bin/hostveil"),
        );
        assert!(cmd.is_none());
    }

    #[test]
    fn privilege_escalation_skips_version() {
        let cmd = build_privilege_escalation_cmd(
            &[String::from("--version")],
            std::path::Path::new("/bin/hostveil"),
        );
        assert!(cmd.is_none());
    }

    #[test]
    fn privilege_escalation_skips_lifecycle() {
        let cmd = build_privilege_escalation_cmd(
            &[String::from("upgrade")],
            std::path::Path::new("/bin/hostveil"),
        );
        assert!(cmd.is_none());
    }

    #[test]
    fn privilege_escalation_skips_lifecycle_uninstall() {
        let cmd = build_privilege_escalation_cmd(
            &[String::from("uninstall")],
            std::path::Path::new("/bin/hostveil"),
        );
        assert!(cmd.is_none());
    }

    #[test]
    fn privilege_escalation_skips_lifecycle_auto_upgrade() {
        let cmd = build_privilege_escalation_cmd(
            &[String::from("auto-upgrade"), String::from("disable")],
            std::path::Path::new("/bin/hostveil"),
        );
        assert!(cmd.is_none());
    }

    #[test]
    fn privilege_escalation_returns_some_for_setup() {
        #[cfg(unix)]
        {
            let cmd = build_privilege_escalation_cmd(
                &[String::from("setup")],
                std::path::Path::new("/bin/hostveil"),
            );
            assert!(cmd.is_some());
        }
    }

    #[test]
    fn privilege_escalation_returns_some_for_scan() {
        #[cfg(unix)]
        {
            let cmd = build_privilege_escalation_cmd(
                &[String::from("--json")],
                std::path::Path::new("/bin/hostveil"),
            );
            assert!(cmd.is_some());
        }
    }

    #[test]
    fn privilege_escalation_returns_some_for_compose_file_scan() {
        #[cfg(unix)]
        {
            let cmd = build_privilege_escalation_cmd(
                &[
                    String::from("--compose"),
                    String::from("docker-compose.yml"),
                ],
                std::path::Path::new("/bin/hostveil"),
            );
            assert!(cmd.is_some());
        }
    }

    #[test]
    fn privilege_escalation_returns_some_for_fix_preview() {
        #[cfg(unix)]
        {
            let cmd = build_privilege_escalation_cmd(
                &[
                    String::from("--fix"),
                    String::from("docker-compose.yml"),
                    String::from("--preview-changes"),
                ],
                std::path::Path::new("/bin/hostveil"),
            );
            assert!(cmd.is_some());
        }
    }

    #[test]
    fn preview_flag_does_not_apply_changes() {
        let root = temp_compose_dir("preview-only");
        let path = root.join("docker-compose.yml");
        write_compose(
            &path,
            concat!(
                "services:\n",
                "  app:\n",
                "    image: alpine:3.20\n",
                "    privileged: true\n",
            ),
        );

        run([
            String::from("--auto-fix"),
            path.display().to_string(),
            String::from("--preview-changes"),
        ])
        .expect("preview should succeed");

        // File should NOT have been modified (no backup, no changes)
        let content = fs::read_to_string(&path).expect("compose file should be readable");
        assert!(
            content.contains("privileged: true"),
            "preview should not modify compose file"
        );
        let backup_exists = fs::read_dir(&root)
            .expect("root dir should be readable")
            .filter_map(|entry| entry.ok())
            .any(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.contains(".bak."))
            });
        assert!(!backup_exists, "preview should not create backup");

        fs::remove_dir_all(root).expect("temp dir should be removed");
    }

    #[test]
    fn fix_requires_target_path() {
        let error = run([
            String::from("--fix"),
            String::from("/nonexistent/hostveil/compose.yml"),
        ])
        .expect_err("--fix with nonexistent path should error");

        assert!(
            matches!(
                error,
                AppError::Fix(..) | AppError::InvalidArgumentCombination(..)
            ),
            "expected Fix or InvalidArgumentCombination error, got {:?}",
            error
        );
    }

    #[test]
    fn auto_fix_without_yes_cancels_without_changes() {
        let root = temp_compose_dir("auto-fix-no-yes");
        let path = root.join("docker-compose.yml");
        write_compose(
            &path,
            concat!(
                "services:\n",
                "  app:\n",
                "    image: alpine:3.20\n",
                "    privileged: true\n",
            ),
        );

        // Without --yes, auto-fix prints the preview, asks for confirmation,
        // gets N (no TTY) and cancels — no changes written.
        run([String::from("--auto-fix"), path.display().to_string()])
            .expect("auto-fix without --yes should gracefully cancel (Ok)");

        let content = fs::read_to_string(&path).expect("compose file should be readable");
        assert!(
            content.contains("privileged: true"),
            "file should remain unchanged when cancelled"
        );
        // Verify no backup was created
        let backup_exists = fs::read_dir(&root)
            .expect("root dir should be readable")
            .filter_map(|entry| entry.ok())
            .any(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.contains(".bak."))
            });
        assert!(!backup_exists, "cancelled fix should not create backup");

        fs::remove_dir_all(root).expect("temp dir should be removed");
    }

    #[test]
    fn fix_preview_without_yes_shows_review_and_does_not_apply() {
        // --fix without --yes needs TTY for review, but with --preview-changes it
        // should just print the review and exit before requiring TTY.
        let root = temp_compose_dir("fix-preview-only");
        let path = root.join("docker-compose.yml");
        write_compose(
            &path,
            concat!(
                "services:\n",
                "  app:\n",
                "    image: alpine:3.20\n",
                "    privileged: true\n",
            ),
        );

        run([
            String::from("--fix"),
            path.display().to_string(),
            String::from("--preview-changes"),
        ])
        .expect("--fix --preview-changes should succeed without TTY");

        let content = fs::read_to_string(&path).expect("compose file should be readable");
        assert!(
            content.contains("privileged: true"),
            "preview should not modify compose file"
        );

        fs::remove_dir_all(root).expect("temp dir should be removed");
    }
}
