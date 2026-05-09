use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dialoguer::{MultiSelect, theme::ColorfulTheme};
use serde::Deserialize;

use super::{AppError, SetupConfig, SetupTool};

const OS_RELEASE_PATH: &str = "/etc/os-release";
const DOCKLE_RELEASE_API_URL: &str =
    "https://api.github.com/repos/goodwithtech/dockle/releases/latest";
const DOCKLE_RELEASES_PAGE_URL: &str = "https://github.com/goodwithtech/dockle/releases";
const TRIVY_APT_KEY_URL: &str = "https://aquasecurity.github.io/trivy-repo/deb/public.key";
const TRIVY_APT_KEYRING_PATH: &str = "/etc/apt/keyrings/trivy.gpg";
const TRIVY_APT_SOURCE_PATH: &str = "/etc/apt/sources.list.d/trivy.list";
const TRIVY_APT_SOURCE_LINE: &str = "deb [signed-by=/etc/apt/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main\n";
const FAIL2BAN_BASELINE_PATH: &str = "/etc/fail2ban/jail.d/hostveil.local";
const FAIL2BAN_BASELINE_CONTENT: &str = concat!(
    "[sshd]\n",
    "enabled = true\n",
    "backend = systemd\n",
    "bantime = 1h\n",
    "findtime = 10m\n",
    "maxretry = 5\n"
);

#[derive(Debug, Clone, PartialEq, Eq)]
struct SetupPlan {
    distro: DistroInfo,
    tools: Vec<SetupTool>,
    steps: Vec<SetupStep>,
    manual_tools: Vec<SetupTool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CpuArchitecture {
    X86_64,
    Aarch64,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DocklePackageFormat {
    Deb,
    Rpm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DockleInstallRequest {
    package_format: DocklePackageFormat,
    architecture: CpuArchitecture,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DockleInstallTarget {
    version: String,
    package_name: String,
    package_url: String,
    checksum_url: String,
    package_format: DocklePackageFormat,
}

#[derive(Debug, Deserialize)]
struct DockleReleaseResponse {
    tag_name: String,
    assets: Vec<DockleReleaseAsset>,
}

#[derive(Debug, Deserialize)]
struct DockleReleaseAsset {
    name: String,
    browser_download_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SetupState {
    installed_tools: BTreeSet<SetupTool>,
    fail2ban_baseline_ready: bool,
}

impl SetupPlan {
    fn new(distro: DistroInfo, tools: Vec<SetupTool>) -> Result<Self, AppError> {
        let state = SetupState::detect(&tools);
        Self::new_with_state(distro, detect_architecture(), tools, &state)
    }

    fn new_with_state(
        distro: DistroInfo,
        architecture: CpuArchitecture,
        tools: Vec<SetupTool>,
        state: &SetupState,
    ) -> Result<Self, AppError> {
        let mut package_set = Vec::new();
        let mut steps = Vec::new();
        let mut manual_tools = Vec::new();

        for tool in &tools {
            if *tool == SetupTool::Trivy
                && distro.family == DistroFamily::Debian
                && !state.tool_is_installed(SetupTool::Trivy)
            {
                steps.push(SetupStep::ConfigureTrivyAptRepo);
            }

            if !state.tool_is_installed(*tool) {
                if *tool == SetupTool::Dockle {
                    match dockle_install_request(distro.family, architecture) {
                        Some(request) => steps.push(SetupStep::InstallDocklePackage(request)),
                        None => {
                            manual_tools.push(*tool);
                            steps.push(SetupStep::ManualInstall {
                                tool: tool.display_name(),
                                instruction: String::from(DOCKLE_RELEASES_PAGE_URL),
                            });
                        }
                    }
                } else {
                    package_set.push(tool.package_name().to_owned());
                }
            }
        }

        package_set.sort();
        package_set.dedup();

        match distro.family {
            DistroFamily::Fedora => {
                if !package_set.is_empty() {
                    steps.push(SetupStep::DnfInstall(package_set));
                }
            }
            DistroFamily::Debian => {
                if !package_set.is_empty() {
                    steps.push(SetupStep::AptInstall(package_set));
                }
            }
            DistroFamily::Unsupported => {
                if !package_set.is_empty() {
                    return Err(AppError::Io(io::Error::other(format!(
                        "{} {}",
                        t!("app.setup.error.unsupported_os").into_owned(),
                        distro.pretty_name
                    ))));
                }
                // Allow manual-only tools on unsupported distros
            }
        }

        if tools.contains(&SetupTool::Fail2Ban) && !state.fail2ban_baseline_ready {
            steps.push(SetupStep::ConfigureFail2BanBaseline);
        }

        Ok(Self {
            distro,
            tools,
            steps,
            manual_tools,
        })
    }

    fn requires_privileges(&self) -> bool {
        !self.steps.is_empty()
    }
}

impl SetupState {
    fn detect(tools: &[SetupTool]) -> Self {
        let installed_tools = tools
            .iter()
            .copied()
            .filter(|tool| command_exists(tool.detection_command()))
            .collect();

        Self {
            installed_tools,
            fail2ban_baseline_ready: tools.contains(&SetupTool::Fail2Ban)
                && fail2ban_baseline_is_ready(),
        }
    }

    fn tool_is_installed(&self, tool: SetupTool) -> bool {
        self.installed_tools.contains(&tool)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SetupStep {
    DnfInstall(Vec<String>),
    AptInstall(Vec<String>),
    ConfigureTrivyAptRepo,
    ConfigureFail2BanBaseline,
    InstallDocklePackage(DockleInstallRequest),
    ManualInstall { tool: String, instruction: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DistroInfo {
    family: DistroFamily,
    pretty_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DistroFamily {
    Fedora,
    Debian,
    Unsupported,
}

pub fn run(config: &SetupConfig) -> Result<(), AppError> {
    let tools = resolve_requested_tools(config)?;
    if tools.is_empty() {
        println!("{}", t!("app.setup.skipped").into_owned());
        return Ok(());
    }

    let distro = detect_distro()?;
    let plan = SetupPlan::new(distro, tools)?;

    print_plan(&plan);

    if !config.assume_yes && io::stdin().is_terminal() && io::stdout().is_terminal() {
        let prompt = t!("app.setup.prompt_confirm_default_yes").into_owned();
        let confirmed = prompt_yes_no_default_yes(&prompt)?;
        if !confirmed {
            println!("{}", t!("app.setup.skipped").into_owned());
            return Ok(());
        }
    }

    if plan.requires_privileges() {
        ensure_sudo_session()?;
    }

    execute_plan(&plan)?;
    print_verification(&plan);

    Ok(())
}

fn resolve_requested_tools(config: &SetupConfig) -> Result<Vec<SetupTool>, AppError> {
    resolve_requested_tools_with_terminal(
        config,
        io::stdin().is_terminal() && io::stdout().is_terminal(),
    )
}

fn resolve_requested_tools_with_terminal(
    config: &SetupConfig,
    has_interactive_terminal: bool,
) -> Result<Vec<SetupTool>, AppError> {
    if let Some(selected_tools) = &config.selected_tools {
        return Ok(selected_tools.clone());
    }

    if config.assume_yes {
        return Ok(recommended_tools());
    }

    if !has_interactive_terminal {
        return Err(AppError::InvalidArgumentCombination(
            crate::i18n::tr_setup_requires_terminal_or_explicit_tools(),
        ));
    }

    println!("{}", t!("app.setup.prompt_tools_help").into_owned());

    let labels = SetupTool::ALL
        .into_iter()
        .map(SetupTool::prompt_label)
        .collect::<Vec<_>>();
    let defaults = SetupTool::ALL
        .into_iter()
        .map(|tool| tool.recommended())
        .collect::<Vec<_>>();

    let selection = MultiSelect::with_theme(&ColorfulTheme::default())
        .with_prompt(t!("app.setup.prompt_tools").into_owned())
        .items(&labels)
        .defaults(&defaults)
        .report(false)
        .interact_opt()
        .map_err(|error| AppError::Io(io::Error::other(error.to_string())))?;

    let Some(selection) = selection else {
        return Ok(Vec::new());
    };

    Ok(selection
        .into_iter()
        .map(|index| SetupTool::ALL[index])
        .collect())
}

fn prompt_yes_no_default_yes(prompt: &str) -> Result<bool, AppError> {
    loop {
        print!("{prompt}");
        io::stdout().flush()?;

        let mut answer = String::new();
        io::stdin().read_line(&mut answer)?;
        match answer.trim().to_ascii_lowercase().as_str() {
            "" | "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => {
                println!("{}", t!("app.setup.prompt_invalid_yes_no").into_owned());
            }
        }
    }
}

fn recommended_tools() -> Vec<SetupTool> {
    SetupTool::ALL
        .into_iter()
        .filter(|tool| tool.recommended())
        .collect()
}

fn detect_architecture() -> CpuArchitecture {
    parse_architecture(env::consts::ARCH)
}

fn parse_architecture(value: &str) -> CpuArchitecture {
    match value {
        "x86_64" => CpuArchitecture::X86_64,
        "aarch64" => CpuArchitecture::Aarch64,
        _ => CpuArchitecture::Unsupported,
    }
}

fn detect_distro() -> Result<DistroInfo, AppError> {
    let text = fs::read_to_string(OS_RELEASE_PATH)?;
    Ok(parse_os_release(&text))
}

fn parse_os_release(text: &str) -> DistroInfo {
    let mut values = BTreeMap::new();

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        values.insert(key.trim().to_owned(), trim_os_release_value(value));
    }

    let pretty_name = values
        .get("PRETTY_NAME")
        .cloned()
        .or_else(|| values.get("NAME").cloned())
        .unwrap_or_else(|| String::from("Linux"));

    let id = values.get("ID").map(|value| value.to_ascii_lowercase());
    let id_like = values
        .get("ID_LIKE")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();

    let family = match id.as_deref() {
        Some("fedora") | Some("rhel") | Some("centos") => DistroFamily::Fedora,
        Some("debian") | Some("ubuntu") => DistroFamily::Debian,
        _ if id_like.contains("fedora") || id_like.contains("rhel") => DistroFamily::Fedora,
        _ if id_like.contains("debian") => DistroFamily::Debian,
        _ => DistroFamily::Unsupported,
    };

    DistroInfo {
        family,
        pretty_name,
    }
}

fn trim_os_release_value(value: &str) -> String {
    value.trim().trim_matches('"').trim_matches('\'').to_owned()
}

fn print_plan(plan: &SetupPlan) {
    println!("{}", t!("app.setup.heading").into_owned());
    println!(
        "{}",
        t!(
            "app.setup.detected_os",
            name = plan.distro.pretty_name.as_str()
        )
        .into_owned()
    );
    println!(
        "{}",
        t!(
            "app.setup.selected_tools",
            tools = plan
                .tools
                .iter()
                .map(|tool| tool.display_name())
                .collect::<Vec<_>>()
                .join(", ")
        )
        .into_owned()
    );
    println!();
    println!("{}", t!("app.setup.planned_changes").into_owned());

    for step in &plan.steps {
        println!("- {}", step.summary());
    }

    println!();
}

fn execute_plan(plan: &SetupPlan) -> Result<(), AppError> {
    for step in &plan.steps {
        println!(
            "{}",
            t!("app.setup.running_step", step = step.summary()).into_owned()
        );
        match step {
            SetupStep::DnfInstall(packages) => {
                let args = vec!["install", "-y"]
                    .into_iter()
                    .chain(packages.iter().map(String::as_str))
                    .collect::<Vec<_>>();
                run_privileged_command("dnf", &args)?;
            }
            SetupStep::AptInstall(packages) => {
                run_privileged_command("apt-get", &["update"])?;
                let args = vec!["install", "-y"]
                    .into_iter()
                    .chain(packages.iter().map(String::as_str))
                    .collect::<Vec<_>>();
                run_privileged_command("apt-get", &args)?;
            }
            SetupStep::ConfigureTrivyAptRepo => {
                configure_trivy_apt_repo()?;
            }
            SetupStep::ConfigureFail2BanBaseline => {
                configure_fail2ban_baseline()?;
            }
            SetupStep::InstallDocklePackage(request) => {
                install_dockle_package(*request)?;
            }
            SetupStep::ManualInstall { tool, instruction } => {
                println!(
                    "{}",
                    t!(
                        "app.setup.manual_install",
                        tool = tool.as_str(),
                        instruction = instruction.as_str()
                    )
                    .into_owned()
                );
            }
        }
    }

    Ok(())
}

fn dockle_install_request(
    distro_family: DistroFamily,
    architecture: CpuArchitecture,
) -> Option<DockleInstallRequest> {
    let package_format = match distro_family {
        DistroFamily::Debian => DocklePackageFormat::Deb,
        DistroFamily::Fedora => DocklePackageFormat::Rpm,
        DistroFamily::Unsupported => return None,
    };

    match architecture {
        CpuArchitecture::X86_64 | CpuArchitecture::Aarch64 => Some(DockleInstallRequest {
            package_format,
            architecture,
        }),
        CpuArchitecture::Unsupported => None,
    }
}

fn install_dockle_package(request: DockleInstallRequest) -> Result<(), AppError> {
    let release = resolve_latest_dockle_release()?;
    let target = select_dockle_install_target(&release, request)?;

    let package_path = temp_named_path("dockle-package", &target.package_name);
    let checksum_path = temp_named_path(
        "dockle-checksums",
        &dockle_checksums_asset_name(&target.version),
    );

    download_to_path(&target.package_url, &package_path)?;
    download_to_path(&target.checksum_url, &checksum_path)?;

    let cleanup_result = (|| -> Result<(), AppError> {
        let checksums_text = fs::read_to_string(&checksum_path)?;
        let expected_checksum = parse_dockle_checksums(&checksums_text)
            .get(&target.package_name)
            .cloned()
            .ok_or_else(|| {
                AppError::Io(io::Error::other(format!(
                    "checksum for {} was not found in {}",
                    target.package_name,
                    checksum_path.display()
                )))
            })?;
        verify_file_sha256(&package_path, &expected_checksum)?;
        install_local_dockle_package(&package_path, target.package_format)
    })();

    let _ = fs::remove_file(&package_path);
    let _ = fs::remove_file(&checksum_path);
    cleanup_result
}

fn resolve_latest_dockle_release() -> Result<DockleReleaseResponse, AppError> {
    let api_url = env::var("HOSTVEIL_DOCKLE_RELEASE_API_URL")
        .unwrap_or_else(|_| String::from(DOCKLE_RELEASE_API_URL));
    let bytes = capture_command_bytes(
        "curl",
        &[
            "-fsSL",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            "User-Agent: hostveil-setup",
            api_url.as_str(),
        ],
    )?;
    serde_json::from_slice(&bytes)
        .map_err(|error| AppError::Io(io::Error::other(error.to_string())))
}

fn select_dockle_install_target(
    release: &DockleReleaseResponse,
    request: DockleInstallRequest,
) -> Result<DockleInstallTarget, AppError> {
    let version = release
        .tag_name
        .strip_prefix('v')
        .unwrap_or(release.tag_name.as_str())
        .to_owned();
    let package_name = dockle_package_asset_name(&version, request)?;
    let checksum_name = dockle_checksums_asset_name(&version);

    let package_url = release
        .assets
        .iter()
        .find(|asset| asset.name == package_name)
        .map(|asset| asset.browser_download_url.clone())
        .ok_or_else(|| {
            AppError::Io(io::Error::other(format!(
                "latest Dockle release is missing expected asset {package_name}"
            )))
        })?;
    let checksum_url = release
        .assets
        .iter()
        .find(|asset| asset.name == checksum_name)
        .map(|asset| asset.browser_download_url.clone())
        .ok_or_else(|| {
            AppError::Io(io::Error::other(format!(
                "latest Dockle release is missing expected asset {checksum_name}"
            )))
        })?;

    Ok(DockleInstallTarget {
        version,
        package_name,
        package_url,
        checksum_url,
        package_format: request.package_format,
    })
}

fn dockle_package_asset_name(
    version: &str,
    request: DockleInstallRequest,
) -> Result<String, AppError> {
    let arch = match request.architecture {
        CpuArchitecture::X86_64 => "Linux-64bit",
        CpuArchitecture::Aarch64 => "Linux-ARM64",
        CpuArchitecture::Unsupported => {
            return Err(AppError::Io(io::Error::other(
                "Dockle package asset mapping is unavailable for this CPU architecture",
            )));
        }
    };
    let extension = match request.package_format {
        DocklePackageFormat::Deb => "deb",
        DocklePackageFormat::Rpm => "rpm",
    };

    Ok(format!("dockle_{version}_{arch}.{extension}"))
}

fn dockle_checksums_asset_name(version: &str) -> String {
    format!("dockle_{version}_checksums.txt")
}

fn parse_dockle_checksums(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let checksum = parts.next()?;
            let filename = parts.next()?;
            Some((filename.to_owned(), checksum.to_owned()))
        })
        .collect()
}

fn download_to_path(url: &str, path: &Path) -> Result<(), AppError> {
    let path_text = path
        .to_str()
        .ok_or_else(|| AppError::Io(io::Error::other("temporary path is not valid UTF-8")))?;
    run_command("curl", &["-fsSL", "-o", path_text, url])
        .map(|_| ())
        .map_err(|error| AppError::Io(io::Error::other(error)))
}

fn verify_file_sha256(path: &Path, expected_checksum: &str) -> Result<(), AppError> {
    let actual_checksum = sha256sum(path)?;
    if actual_checksum.eq_ignore_ascii_case(expected_checksum) {
        Ok(())
    } else {
        Err(AppError::Io(io::Error::other(format!(
            "checksum mismatch for {}: expected {}, got {}",
            path.display(),
            expected_checksum,
            actual_checksum
        ))))
    }
}

fn sha256sum(path: &Path) -> Result<String, AppError> {
    let path_text = path
        .to_str()
        .ok_or_else(|| AppError::Io(io::Error::other("temporary path is not valid UTF-8")))?;
    let output = run_command("sha256sum", &[path_text])
        .map_err(|error| AppError::Io(io::Error::other(error)))?;
    output
        .split_whitespace()
        .next()
        .map(str::to_owned)
        .ok_or_else(|| AppError::Io(io::Error::other("sha256sum did not return a checksum")))
}

fn install_local_dockle_package(
    package_path: &Path,
    package_format: DocklePackageFormat,
) -> Result<(), AppError> {
    let path_text = package_path
        .to_str()
        .ok_or_else(|| AppError::Io(io::Error::other("temporary path is not valid UTF-8")))?;

    match package_format {
        DocklePackageFormat::Deb => {
            run_privileged_command("apt-get", &["install", "-y", path_text]).map(|_| ())
        }
        DocklePackageFormat::Rpm => {
            run_privileged_command("dnf", &["install", "-y", path_text]).map(|_| ())
        }
    }
}

fn configure_trivy_apt_repo() -> Result<(), AppError> {
    run_privileged_command("apt-get", &["update"])?;
    run_privileged_command(
        "apt-get",
        &["install", "-y", "ca-certificates", "curl", "gnupg"],
    )?;
    run_privileged_command("install", &["-d", "-m", "0755", "/etc/apt/keyrings"])?;

    let key_bytes = capture_command_bytes("curl", &["-fsSL", TRIVY_APT_KEY_URL])?;
    run_privileged_command_with_stdin(
        "gpg",
        &[
            "--dearmor",
            "--batch",
            "--yes",
            "-o",
            TRIVY_APT_KEYRING_PATH,
        ],
        &key_bytes,
    )?;

    install_root_file(
        TRIVY_APT_SOURCE_PATH,
        "0644",
        TRIVY_APT_SOURCE_LINE.as_bytes(),
    )?;
    Ok(())
}

fn configure_fail2ban_baseline() -> Result<(), AppError> {
    install_root_file(
        FAIL2BAN_BASELINE_PATH,
        "0644",
        FAIL2BAN_BASELINE_CONTENT.as_bytes(),
    )?;
    run_privileged_command("fail2ban-client", &["-t"])?;
    run_privileged_command("systemctl", &["enable", "--now", "fail2ban"])?;
    wait_for_privileged_command(
        "systemctl",
        &["is-active", "--quiet", "fail2ban"],
        10,
        Duration::from_millis(500),
    )?;
    wait_for_privileged_command(
        "fail2ban-client",
        &["status"],
        10,
        Duration::from_millis(500),
    )?;
    wait_for_privileged_command(
        "fail2ban-client",
        &["status", "sshd"],
        10,
        Duration::from_millis(500),
    )?;
    Ok(())
}

fn print_verification(plan: &SetupPlan) {
    println!();
    println!("{}", t!("app.setup.verification_heading").into_owned());

    for tool in &plan.tools {
        if plan.manual_tools.contains(tool) {
            println!(
                "- {}: {}",
                tool.display_name(),
                t!("app.setup.manual_guidance_provided").into_owned()
            );
            continue;
        }
        match tool {
            SetupTool::Lynis => print_command_check("lynis", &["--version"]),
            SetupTool::Trivy => print_command_check("trivy", &["--version"]),
            SetupTool::Dockle => print_command_check("dockle", &["--version"]),
            SetupTool::Fail2Ban => {
                print_command_check("systemctl", &["is-enabled", "fail2ban"]);
                print_command_check("systemctl", &["is-active", "fail2ban"]);
            }
        }
    }

    println!();
    if plan.manual_tools.is_empty() {
        println!("{}", t!("app.setup.complete").into_owned());
    } else {
        println!(
            "{}",
            t!("app.setup.complete_with_manual_steps").into_owned()
        );
    }
}

fn print_command_check(program: &str, args: &[&str]) {
    match run_command(program, args) {
        Ok(output) => println!("- {}", output),
        Err(error) => println!(
            "- {}",
            t!(
                "app.setup.check_failed",
                command = format_command(program, args).as_str(),
                detail = error.as_str()
            )
            .into_owned()
        ),
    }
}

fn ensure_sudo_session() -> Result<(), AppError> {
    if is_effective_root() {
        return Ok(());
    }

    if !command_exists("sudo") {
        return Err(AppError::Io(io::Error::other(
            crate::i18n::tr_setup_sudo_missing(),
        )));
    }

    if run_command("sudo", &["-n", "true"]).is_ok() {
        return Ok(());
    }

    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(AppError::Io(io::Error::other(
            crate::i18n::tr_setup_sudo_needs_terminal(),
        )));
    }

    println!("{}", t!("app.setup.requesting_sudo").into_owned());
    run_command("sudo", &["-v"]).map(|_| ()).map_err(|error| {
        AppError::Io(io::Error::other(
            crate::i18n::tr_setup_sudo_credentials_failed(&error),
        ))
    })
}

fn command_exists(program: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!(
            "command -v {} >/dev/null 2>&1",
            shell_escape(program)
        ))
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn fail2ban_baseline_is_ready() -> bool {
    if !command_exists("systemctl") {
        return false;
    }

    let baseline = match fs::read_to_string(FAIL2BAN_BASELINE_PATH) {
        Ok(baseline) => baseline,
        Err(_) => return false,
    };

    normalize_file_content(&baseline) == normalize_file_content(FAIL2BAN_BASELINE_CONTENT)
        && run_command("systemctl", &["is-enabled", "fail2ban"]).is_ok()
        && run_command("systemctl", &["is-active", "fail2ban"]).is_ok()
}

fn normalize_file_content(content: &str) -> &str {
    content.trim_end_matches(['\r', '\n'])
}

fn shell_escape(value: &str) -> String {
    value.replace('"', "\\\"")
}

fn is_effective_root() -> bool {
    run_command("id", &["-u"])
        .map(|output| output.trim() == "0")
        .unwrap_or(false)
}

fn run_command(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| error.to_string())?;
    command_output_to_result(program, args, output)
}

fn capture_command_bytes(program: &str, args: &[&str]) -> Result<Vec<u8>, AppError> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| AppError::Io(io::Error::other(error.to_string())))?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(AppError::Io(io::Error::other(command_error_detail(
            program, args, &output,
        ))))
    }
}

fn run_privileged_command(program: &str, args: &[&str]) -> Result<String, AppError> {
    let output = privileged_command(program, args)
        .output()
        .map_err(|error| AppError::Io(io::Error::other(error.to_string())))?;
    command_output_to_result(program, args, output)
        .map_err(|error| AppError::Io(io::Error::other(error)))
}

fn wait_for_privileged_command(
    program: &str,
    args: &[&str],
    retries: usize,
    delay: Duration,
) -> Result<String, AppError> {
    let mut last_error = None;

    for attempt in 0..retries {
        match run_privileged_command(program, args) {
            Ok(output) => return Ok(output),
            Err(error) => {
                last_error = Some(error);
                if attempt + 1 < retries {
                    thread::sleep(delay);
                }
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        AppError::Io(io::Error::other(format!(
            "{} did not succeed after {} attempt(s)",
            format_command(program, args),
            retries
        )))
    }))
}

fn run_privileged_command_with_stdin(
    program: &str,
    args: &[&str],
    stdin_bytes: &[u8],
) -> Result<(), AppError> {
    let mut child = privileged_command(program, args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| AppError::Io(io::Error::other(error.to_string())))?;

    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(stdin_bytes)?;
    }

    let output = child
        .wait_with_output()
        .map_err(|error| AppError::Io(io::Error::other(error.to_string())))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(AppError::Io(io::Error::other(command_error_detail(
            program, args, &output,
        ))))
    }
}

fn privileged_command(program: &str, args: &[&str]) -> Command {
    if is_effective_root() {
        let mut command = Command::new(program);
        command.args(args);
        command
    } else {
        let mut command = Command::new("sudo");
        command.arg(program).args(args);
        command
    }
}

fn command_output_to_result(
    program: &str,
    args: &[&str],
    output: Output,
) -> Result<String, String> {
    if !output.status.success() {
        return Err(command_error_detail(program, args, &output));
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if stdout.is_empty() {
        Ok(format_command(program, args))
    } else {
        Ok(stdout)
    }
}

fn command_error_detail(program: &str, args: &[&str], output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    if !stderr.is_empty() {
        return format!("{}: {}", format_command(program, args), stderr);
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if !stdout.is_empty() {
        return format!("{}: {}", format_command(program, args), stdout);
    }

    format!(
        "{} exited with status {}",
        format_command(program, args),
        output.status
    )
}

fn format_command(program: &str, args: &[&str]) -> String {
    if args.is_empty() {
        program.to_owned()
    } else {
        format!("{} {}", program, args.join(" "))
    }
}

fn install_root_file(destination: &str, mode: &str, content: &[u8]) -> Result<(), AppError> {
    let temp_path = temp_path("setup");
    fs::write(&temp_path, content)?;

    let source = temp_path
        .to_str()
        .ok_or_else(|| AppError::Io(io::Error::other("temporary path is not valid UTF-8")))?
        .to_owned();

    let result =
        run_privileged_command("install", &["-D", "-m", mode, source.as_str(), destination]);
    let _ = fs::remove_file(&temp_path);
    result.map(|_| ())
}

fn temp_path(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should move forward")
        .as_nanos();
    std::env::temp_dir().join(format!("hostveil-{prefix}-{}-{nanos}", std::process::id()))
}

fn temp_named_path(prefix: &str, file_name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should move forward")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "hostveil-{prefix}-{}-{nanos}-{file_name}",
        std::process::id()
    ))
}

impl SetupTool {
    fn recommended(self) -> bool {
        matches!(
            self,
            Self::Lynis | Self::Trivy | Self::Dockle | Self::Fail2Ban
        )
    }

    fn package_name(self) -> &'static str {
        self.cli_name()
    }

    fn detection_command(self) -> &'static str {
        match self {
            Self::Lynis => "lynis",
            Self::Trivy => "trivy",
            Self::Dockle => "dockle",
            Self::Fail2Ban => "fail2ban-client",
        }
    }

    fn display_name(self) -> String {
        match self {
            Self::Lynis => t!("app.setup.tool.lynis.name").into_owned(),
            Self::Trivy => t!("app.setup.tool.trivy.name").into_owned(),
            Self::Dockle => t!("app.setup.tool.dockle.name").into_owned(),
            Self::Fail2Ban => t!("app.setup.tool.fail2ban.name").into_owned(),
        }
    }

    fn prompt_label(self) -> String {
        match self {
            Self::Lynis => t!("app.setup.tool.lynis.prompt").into_owned(),
            Self::Trivy => t!("app.setup.tool.trivy.prompt").into_owned(),
            Self::Dockle => t!("app.setup.tool.dockle.prompt").into_owned(),
            Self::Fail2Ban => t!("app.setup.tool.fail2ban.prompt").into_owned(),
        }
    }
}

impl SetupStep {
    fn summary(&self) -> String {
        match self {
            Self::DnfInstall(packages) => t!(
                "app.setup.step.dnf_install",
                packages = packages.join(", ").as_str()
            )
            .into_owned(),
            Self::AptInstall(packages) => t!(
                "app.setup.step.apt_install",
                packages = packages.join(", ").as_str()
            )
            .into_owned(),
            Self::ConfigureTrivyAptRepo => t!("app.setup.step.trivy_repo").into_owned(),
            Self::ConfigureFail2BanBaseline => t!("app.setup.step.fail2ban_baseline").into_owned(),
            Self::InstallDocklePackage(_) => t!("app.setup.step.dockle_package").into_owned(),
            Self::ManualInstall { tool, .. } => {
                t!("app.setup.step.manual_install", tool = tool.as_str()).into_owned()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fedora_os_release() {
        let distro = parse_os_release(
            r#"
NAME="Fedora Linux"
PRETTY_NAME="Fedora Linux 43"
ID=fedora
VERSION_ID=43
ID_LIKE="fedora"
"#,
        );

        assert_eq!(distro.family, DistroFamily::Fedora);
        assert_eq!(distro.pretty_name, "Fedora Linux 43");
    }

    #[test]
    fn parses_ubuntu_as_debian_family() {
        let distro = parse_os_release(
            r#"
PRETTY_NAME="Ubuntu 24.04.4 LTS"
ID=ubuntu
ID_LIKE=debian
"#,
        );

        assert_eq!(distro.family, DistroFamily::Debian);
    }

    #[test]
    fn parses_debian_as_debian_family() {
        let distro = parse_os_release(
            r#"
PRETTY_NAME="Debian GNU/Linux trixie/sid"
ID=debian
"#,
        );

        assert_eq!(distro.family, DistroFamily::Debian);
    }

    #[test]
    fn parses_rocky_as_fedora_family() {
        let distro = parse_os_release(
            r#"
PRETTY_NAME="Rocky Linux 9.5"
ID=rocky
ID_LIKE="rhel centos fedora"
"#,
        );

        assert_eq!(distro.family, DistroFamily::Fedora);
    }

    #[test]
    fn builds_fedora_plan_without_extra_repo_step() {
        let plan = SetupPlan::new_with_state(
            DistroInfo {
                family: DistroFamily::Fedora,
                pretty_name: String::from("Fedora Linux 43"),
            },
            CpuArchitecture::X86_64,
            vec![SetupTool::Lynis, SetupTool::Trivy, SetupTool::Fail2Ban],
            &SetupState {
                installed_tools: BTreeSet::new(),
                fail2ban_baseline_ready: false,
            },
        )
        .expect("fedora plan should build");

        assert_eq!(
            plan.steps,
            vec![
                SetupStep::DnfInstall(vec![
                    String::from("fail2ban"),
                    String::from("lynis"),
                    String::from("trivy"),
                ]),
                SetupStep::ConfigureFail2BanBaseline,
            ]
        );
    }

    #[test]
    fn builds_debian_plan_with_trivy_repo_step() {
        let plan = SetupPlan::new_with_state(
            DistroInfo {
                family: DistroFamily::Debian,
                pretty_name: String::from("Ubuntu 24.04.4 LTS"),
            },
            CpuArchitecture::X86_64,
            vec![SetupTool::Trivy, SetupTool::Fail2Ban],
            &SetupState {
                installed_tools: BTreeSet::new(),
                fail2ban_baseline_ready: false,
            },
        )
        .expect("debian plan should build");

        assert_eq!(
            plan.steps,
            vec![
                SetupStep::ConfigureTrivyAptRepo,
                SetupStep::AptInstall(vec![String::from("fail2ban"), String::from("trivy"),]),
                SetupStep::ConfigureFail2BanBaseline,
            ]
        );
    }

    #[test]
    fn temp_path_uses_requested_prefix() {
        let path = temp_path("trivy");
        let path_text = path.display().to_string();

        assert!(path_text.contains("hostveil-trivy-"));
    }

    #[test]
    fn skips_steps_when_requested_tools_are_already_ready() {
        let plan = SetupPlan::new_with_state(
            DistroInfo {
                family: DistroFamily::Fedora,
                pretty_name: String::from("Fedora Linux 43"),
            },
            CpuArchitecture::X86_64,
            vec![SetupTool::Lynis, SetupTool::Trivy, SetupTool::Fail2Ban],
            &SetupState {
                installed_tools: [SetupTool::Lynis, SetupTool::Trivy, SetupTool::Fail2Ban]
                    .into_iter()
                    .collect(),
                fail2ban_baseline_ready: true,
            },
        )
        .expect("ready fedora plan should build");

        assert!(plan.steps.is_empty());
    }

    #[test]
    fn normalizes_trailing_newlines_when_comparing_managed_files() {
        assert_eq!(
            normalize_file_content(FAIL2BAN_BASELINE_CONTENT),
            normalize_file_content(
                "[sshd]\nenabled = true\nbackend = systemd\nbantime = 1h\nfindtime = 10m\nmaxretry = 5"
            )
        );
    }

    #[test]
    fn setup_terminal_requirement_uses_translation_helper_detail() {
        let error = resolve_requested_tools_with_terminal(&SetupConfig::default(), false)
            .expect_err("non-interactive setup should require explicit tools");

        assert!(matches!(
            error,
            AppError::InvalidArgumentCombination(message)
                if message == crate::i18n::tr_setup_requires_terminal_or_explicit_tools()
        ));
    }

    #[test]
    fn unsupported_distro_allows_manual_only_tools() {
        let plan = SetupPlan::new_with_state(
            DistroInfo {
                family: DistroFamily::Unsupported,
                pretty_name: String::from("Arch Linux"),
            },
            CpuArchitecture::X86_64,
            vec![SetupTool::Dockle],
            &SetupState {
                installed_tools: BTreeSet::new(),
                fail2ban_baseline_ready: false,
            },
        )
        .expect("unsupported distro should allow manual-only tools");

        assert_eq!(plan.manual_tools, vec![SetupTool::Dockle]);
        assert_eq!(plan.steps.len(), 1);
        assert!(matches!(
            plan.steps[0],
            SetupStep::ManualInstall { ref tool, .. } if tool == "Dockle"
        ));
    }

    #[test]
    fn unsupported_distro_rejects_auto_installable_tools() {
        let result = SetupPlan::new_with_state(
            DistroInfo {
                family: DistroFamily::Unsupported,
                pretty_name: String::from("Arch Linux"),
            },
            CpuArchitecture::X86_64,
            vec![SetupTool::Lynis],
            &SetupState {
                installed_tools: BTreeSet::new(),
                fail2ban_baseline_ready: false,
            },
        );

        assert!(result.is_err());
    }

    #[test]
    fn parses_supported_architectures() {
        assert_eq!(parse_architecture("x86_64"), CpuArchitecture::X86_64);
        assert_eq!(parse_architecture("aarch64"), CpuArchitecture::Aarch64);
        assert_eq!(parse_architecture("armv7l"), CpuArchitecture::Unsupported);
    }

    #[test]
    fn dockle_is_recommended_by_default() {
        assert_eq!(
            recommended_tools(),
            vec![
                SetupTool::Lynis,
                SetupTool::Trivy,
                SetupTool::Dockle,
                SetupTool::Fail2Ban
            ]
        );
    }

    #[test]
    fn builds_debian_plan_with_dockle_install_step() {
        let plan = SetupPlan::new_with_state(
            DistroInfo {
                family: DistroFamily::Debian,
                pretty_name: String::from("Ubuntu 24.04.4 LTS"),
            },
            CpuArchitecture::Aarch64,
            vec![SetupTool::Dockle],
            &SetupState {
                installed_tools: BTreeSet::new(),
                fail2ban_baseline_ready: false,
            },
        )
        .expect("debian dockle plan should build");

        assert!(plan.manual_tools.is_empty());
        assert_eq!(
            plan.steps,
            vec![SetupStep::InstallDocklePackage(DockleInstallRequest {
                package_format: DocklePackageFormat::Deb,
                architecture: CpuArchitecture::Aarch64,
            })]
        );
    }

    #[test]
    fn builds_fedora_plan_with_dockle_install_step() {
        let plan = SetupPlan::new_with_state(
            DistroInfo {
                family: DistroFamily::Fedora,
                pretty_name: String::from("Fedora Linux 43"),
            },
            CpuArchitecture::X86_64,
            vec![SetupTool::Dockle, SetupTool::Lynis],
            &SetupState {
                installed_tools: BTreeSet::new(),
                fail2ban_baseline_ready: false,
            },
        )
        .expect("plan should build");

        assert!(plan.manual_tools.is_empty());
        assert!(plan.steps.iter().any(|s| matches!(
            s,
            SetupStep::InstallDocklePackage(DockleInstallRequest {
                package_format: DocklePackageFormat::Rpm,
                architecture: CpuArchitecture::X86_64,
            })
        )));
        assert!(plan.steps.iter().any(|s| matches!(
            s,
            SetupStep::DnfInstall(pkgs) if pkgs.contains(&String::from("lynis"))
        )));
    }

    #[test]
    fn unsupported_architecture_falls_back_to_manual_dockle_guidance() {
        let plan = SetupPlan::new_with_state(
            DistroInfo {
                family: DistroFamily::Fedora,
                pretty_name: String::from("Fedora Linux 43"),
            },
            CpuArchitecture::Unsupported,
            vec![SetupTool::Dockle],
            &SetupState {
                installed_tools: BTreeSet::new(),
                fail2ban_baseline_ready: false,
            },
        )
        .expect("unsupported arch should keep manual dockle guidance");

        assert_eq!(plan.manual_tools, vec![SetupTool::Dockle]);
        assert!(matches!(
            plan.steps[0],
            SetupStep::ManualInstall { ref tool, .. } if tool == "Dockle"
        ));
    }

    #[test]
    fn chooses_expected_debian_dockle_asset_names() {
        let name = dockle_package_asset_name(
            "0.4.15",
            DockleInstallRequest {
                package_format: DocklePackageFormat::Deb,
                architecture: CpuArchitecture::X86_64,
            },
        )
        .expect("asset name should resolve");
        let arm64_name = dockle_package_asset_name(
            "0.4.15",
            DockleInstallRequest {
                package_format: DocklePackageFormat::Deb,
                architecture: CpuArchitecture::Aarch64,
            },
        )
        .expect("arm64 asset name should resolve");

        assert_eq!(name, "dockle_0.4.15_Linux-64bit.deb");
        assert_eq!(arm64_name, "dockle_0.4.15_Linux-ARM64.deb");
    }

    #[test]
    fn chooses_expected_fedora_dockle_asset_names() {
        let name = dockle_package_asset_name(
            "0.4.15",
            DockleInstallRequest {
                package_format: DocklePackageFormat::Rpm,
                architecture: CpuArchitecture::X86_64,
            },
        )
        .expect("asset name should resolve");
        let arm64_name = dockle_package_asset_name(
            "0.4.15",
            DockleInstallRequest {
                package_format: DocklePackageFormat::Rpm,
                architecture: CpuArchitecture::Aarch64,
            },
        )
        .expect("arm64 asset name should resolve");

        assert_eq!(name, "dockle_0.4.15_Linux-64bit.rpm");
        assert_eq!(arm64_name, "dockle_0.4.15_Linux-ARM64.rpm");
    }

    #[test]
    fn parses_dockle_checksums_file() {
        let checksums = parse_dockle_checksums(
            "abc123  dockle_0.4.15_Linux-64bit.deb\n\
             def456  dockle_0.4.15_Linux-ARM64.rpm\n",
        );

        assert_eq!(
            checksums.get("dockle_0.4.15_Linux-64bit.deb"),
            Some(&String::from("abc123"))
        );
        assert_eq!(
            checksums.get("dockle_0.4.15_Linux-ARM64.rpm"),
            Some(&String::from("def456"))
        );
    }

    #[test]
    fn selects_dockle_assets_from_release_metadata() {
        let release = DockleReleaseResponse {
            tag_name: String::from("v0.4.15"),
            assets: vec![
                DockleReleaseAsset {
                    name: String::from("dockle_0.4.15_Linux-64bit.deb"),
                    browser_download_url: String::from("https://example.test/dockle.deb"),
                },
                DockleReleaseAsset {
                    name: String::from("dockle_0.4.15_checksums.txt"),
                    browser_download_url: String::from("https://example.test/checksums.txt"),
                },
            ],
        };

        let target = select_dockle_install_target(
            &release,
            DockleInstallRequest {
                package_format: DocklePackageFormat::Deb,
                architecture: CpuArchitecture::X86_64,
            },
        )
        .expect("release metadata should resolve install target");

        assert_eq!(target.version, "0.4.15");
        assert_eq!(target.package_name, "dockle_0.4.15_Linux-64bit.deb");
        assert_eq!(target.package_url, "https://example.test/dockle.deb");
        assert_eq!(target.checksum_url, "https://example.test/checksums.txt");
    }
}
