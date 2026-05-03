use std::collections::BTreeMap;

use crate::compose::{ComposeProject, ComposeService};
use crate::domain::{Axis, Finding, RemediationKind, Severity};

use super::{ServiceFindingText, service_finding_with_remediation};

const DANGEROUS_CAPS: [&str; 5] = [
    "NET_ADMIN",
    "SYS_ADMIN",
    "SYS_PTRACE",
    "SYS_MODULE",
    "DAC_READ_SEARCH",
];

pub fn scan_runtime_risk(project: &ComposeProject) -> Vec<Finding> {
    let mut findings = Vec::new();

    for service in project.services.values() {
        findings.extend(scan_seccomp(service));
        findings.extend(scan_capabilities(service));
    }

    findings
}

fn scan_seccomp(service: &ComposeService) -> Vec<Finding> {
    let mut findings = Vec::new();

    let seccomp_unconfined = service
        .security_opt
        .iter()
        .any(|opt| opt.to_ascii_lowercase().contains("seccomp:unconfined"));

    if seccomp_unconfined {
        findings.push(service_finding_with_remediation(
            "runtime.seccomp_unconfined",
            Axis::ExcessivePermissions,
            Severity::High,
            &service.name,
            ServiceFindingText {
                title: t!("finding.runtime.seccomp_unconfined.title").into_owned(),
                description: t!(
                    "finding.runtime.seccomp_unconfined.description",
                    service = service.name.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.runtime.seccomp_unconfined.why").into_owned(),
                how_to_fix: t!("finding.runtime.seccomp_unconfined.fix").into_owned(),
            },
            BTreeMap::from([(
                String::from("security_opt"),
                String::from("seccomp:unconfined"),
            )]),
            RemediationKind::Safe,
        ));
    }

    findings
}

fn scan_capabilities(service: &ComposeService) -> Vec<Finding> {
    let mut findings = Vec::new();

    if service.privileged {
        return findings;
    }

    let dangerous: Vec<String> = service
        .cap_add
        .iter()
        .filter(|cap| DANGEROUS_CAPS.iter().any(|d| d.eq_ignore_ascii_case(cap)))
        .cloned()
        .collect();

    if !dangerous.is_empty() {
        findings.push(service_finding_with_remediation(
            "runtime.dangerous_capabilities",
            Axis::ExcessivePermissions,
            Severity::High,
            &service.name,
            ServiceFindingText {
                title: t!("finding.runtime.dangerous_capabilities.title").into_owned(),
                description: t!(
                    "finding.runtime.dangerous_capabilities.description",
                    service = service.name.as_str(),
                    capabilities = dangerous.join(", ")
                )
                .into_owned(),
                why_risky: t!("finding.runtime.dangerous_capabilities.why").into_owned(),
                how_to_fix: t!("finding.runtime.dangerous_capabilities.fix").into_owned(),
            },
            BTreeMap::from([(String::from("capabilities"), dangerous.join(", "))]),
            RemediationKind::Safe,
        ));
    }

    findings
}

#[allow(dead_code)]
fn scan_no_new_privileges(service: &ComposeService) -> Vec<Finding> {
    let mut findings = Vec::new();

    let has_no_new_privs = service
        .security_opt
        .iter()
        .any(|opt| opt.to_ascii_lowercase().contains("no-new-privileges:true"));

    if !has_no_new_privs && !service.privileged {
        findings.push(service_finding_with_remediation(
            "runtime.no_new_privileges_disabled",
            Axis::ExcessivePermissions,
            Severity::Low,
            &service.name,
            ServiceFindingText {
                title: t!("finding.runtime.no_new_privileges_disabled.title").into_owned(),
                description: t!(
                    "finding.runtime.no_new_privileges_disabled.description",
                    service = service.name.as_str()
                )
                .into_owned(),
                why_risky: t!("finding.runtime.no_new_privileges_disabled.why").into_owned(),
                how_to_fix: t!("finding.runtime.no_new_privileges_disabled.fix").into_owned(),
            },
            BTreeMap::new(),
            RemediationKind::Safe,
        ));
    }

    findings
}
