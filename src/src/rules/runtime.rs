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
        findings.extend(scan_no_new_privileges(service));
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
            RemediationKind::Auto,
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
            RemediationKind::Auto,
        ));
    }

    findings
}

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
            RemediationKind::Auto,
        ));
    }

    findings
}

#[cfg(test)]
mod tests {
    use crate::compose::ComposeParser;
    use crate::domain::{Axis, RemediationKind, Severity};

    use super::*;

    fn parse(yaml: &str) -> ComposeProject {
        use std::io::Write;
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("hostveil-runtime-test-{}", id));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("docker-compose.yml");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(yaml.as_bytes()).unwrap();
        }
        let project = ComposeParser::parse_path(&path).expect("should parse");
        let _ = std::fs::remove_dir_all(&dir);
        project
    }

    #[test]
    fn detects_seccomp_unconfined() {
        let project = parse("services:\n  app:\n    image: alpine\n    security_opt:\n      - seccomp:unconfined\n");
        let findings = scan_runtime_risk(&project);
        assert_eq!(findings.len(), 2); // seccomp + no_new_privs
        let seccomp = findings.iter().find(|f| f.id == "runtime.seccomp_unconfined").unwrap();
        assert_eq!(seccomp.severity, Severity::High);
        assert_eq!(seccomp.axis, Axis::ExcessivePermissions);
        assert_eq!(seccomp.remediation, RemediationKind::Auto);
    }

    #[test]
    fn detects_dangerous_capabilities() {
        let project = parse("services:\n  app:\n    image: alpine\n    cap_add:\n      - NET_ADMIN\n      - SYS_PTRACE\n");
        let findings = scan_runtime_risk(&project);
        let caps = findings.iter().find(|f| f.id == "runtime.dangerous_capabilities").unwrap();
        assert_eq!(caps.severity, Severity::High);
        assert!(caps.evidence.contains_key("capabilities"));
    }

    #[test]
    fn detects_missing_no_new_privileges() {
        let project = parse("services:\n  app:\n    image: alpine\n");
        let findings = scan_runtime_risk(&project);
        let no_new = findings.iter().find(|f| f.id == "runtime.no_new_privileges_disabled").unwrap();
        assert_eq!(no_new.severity, Severity::Low);
        assert_eq!(no_new.axis, Axis::ExcessivePermissions);
        assert_eq!(no_new.remediation, RemediationKind::Auto);
    }

    #[test]
    fn skips_no_new_privileges_when_set() {
        let project = parse("services:\n  app:\n    image: alpine\n    security_opt:\n      - no-new-privileges:true\n");
        let findings = scan_runtime_risk(&project);
        assert!(!findings.iter().any(|f| f.id == "runtime.no_new_privileges_disabled"));
    }

    #[test]
    fn skips_no_new_privileges_when_privileged() {
        let project = parse("services:\n  app:\n    image: alpine\n    privileged: true\n");
        let findings = scan_runtime_risk(&project);
        assert!(!findings.iter().any(|f| f.id == "runtime.no_new_privileges_disabled"));
    }

    #[test]
    fn hardened_service_stays_clear() {
        let project = parse(
            "services:\n  app:\n    image: alpine\n    security_opt:\n      - no-new-privileges:true\n      - seccomp:default\n"
        );
        let findings = scan_runtime_risk(&project);
        assert!(findings.is_empty());
    }
}
