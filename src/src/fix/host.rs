use std::fs;
use std::io;
use std::path::Path;
use std::process::Command;

use crate::domain::Finding;
use crate::fix::{FixError, FixMode, FixPlan, FixProposal};

pub fn apply_host_fixes(
    host_root: &Path,
    findings: &[Finding],
    filter: Option<&[String]>,
    mode: FixMode,
    plan: &mut FixPlan,
) -> Result<(), FixError> {
    let mut applied = Vec::new();

    // Check if we need to fix ufw
    if has_finding(findings, filter, "host.ufw_installed_but_disabled") {
        if mode == FixMode::Fix {
            let output = Command::new("ufw").arg("enable").output()?;
            if !output.status.success() {
                return Err(FixError::Io(io::Error::other(format!(
                    "ufw enable failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                ))));
            }
        }
        applied.push(FixProposal {
            service: String::from("host"),
            summary: String::from("Enabled UFW firewall"),
        });
    }

    if has_finding(findings, filter, "host.ssh_root_login_enabled") {
        if mode == FixMode::Fix {
            let config_path = host_root.join("etc/ssh/sshd_config");
            let text = fs::read_to_string(&config_path)?;
            let updated = text.replace("PermitRootLogin yes", "PermitRootLogin no");
            fs::write(&config_path, updated)?;

            let output = Command::new("systemctl")
                .arg("reload")
                .arg("sshd")
                .output()?;
            if !output.status.success() {
                return Err(FixError::Io(io::Error::other(format!(
                    "sshd reload failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                ))));
            }
        }
        applied.push(FixProposal {
            service: String::from("host"),
            summary: String::from("Disabled SSH root login"),
        });
    }

    plan.safe_applied.extend(applied);

    Ok(())
}

fn has_finding(findings: &[Finding], filter: Option<&[String]>, id: &str) -> bool {
    findings
        .iter()
        .any(|f| f.id == id && filter.is_none_or(|allowed| allowed.contains(&f.id)))
}
