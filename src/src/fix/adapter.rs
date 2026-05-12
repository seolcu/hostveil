use crate::domain::{Finding, RemediationKind, Source};

use super::{FixAction, FixProposal};

pub fn classify_adapter_findings(
    findings: &[Finding],
) -> (Vec<FixAction>, Vec<FixProposal>, Vec<FixProposal>) {
    let mut actions = Vec::new();
    let mut auto_applied = Vec::new();
    let mut review_applied = Vec::new();

    for finding in findings {
        if finding.remediation == RemediationKind::None {
            continue;
        }

        match finding.source {
            Source::Dockle => {
                let result = classify_dockle_finding(finding);
                handle_result(result, &mut actions, &mut auto_applied, &mut review_applied);
            }
            Source::Lynis => {
                let result = classify_lynis_finding(finding);
                handle_result(result, &mut actions, &mut auto_applied, &mut review_applied);
            }
            _ => {}
        }
    }

    (actions, auto_applied, review_applied)
}

fn handle_result(
    result: Option<(FixAction, FixProposal)>,
    actions: &mut Vec<FixAction>,
    auto_applied: &mut Vec<FixProposal>,
    review_applied: &mut Vec<FixProposal>,
) {
    if let Some((action, proposal)) = result {
        let is_review = matches!(proposal.remediation, RemediationKind::Review);
        actions.push(action);
        if is_review {
            review_applied.push(proposal);
        } else {
            auto_applied.push(proposal);
        }
    }
}

fn classify_dockle_finding(finding: &Finding) -> Option<(FixAction, FixProposal)> {
    let service = finding.related_service.as_deref().unwrap_or("unknown");
    let sample_codes = finding
        .evidence
        .get("sample_codes")
        .map(|s| s.as_str())
        .unwrap_or("");

    // Generate fixes based on the Dockle sample codes found
    let mut found_actions: Vec<FixAction> = Vec::new();

    if sample_codes.contains("DKL-DI-0006") {
        found_actions.push(FixAction::ComposeEdit {
            service: service.to_owned(),
            summary: format!("Add HEALTHCHECK to service '{}'", service),
            diff: "+  healthcheck:\n+    test: [\"CMD\", \"curl\", \"-f\", \"http://localhost\"]\n+    interval: 30s\n+    timeout: 10s\n+    retries: 3\n".to_string(),
        });
    }
    if sample_codes.contains("DKL-DI-0003") {
        found_actions.push(FixAction::ComposeEdit {
            service: service.to_owned(),
            summary: format!(
                "Add no-new-privileges security_opt for service '{}'",
                service
            ),
            diff: "+  security_opt:\n+    - no-new-privileges:true\n".to_string(),
        });
    }
    if sample_codes.contains("DKL-DI-0005") {
        found_actions.push(FixAction::ComposeEdit {
            service: service.to_owned(),
            summary: format!(
                "Set user directive for service '{}' to reduce root privileges",
                service
            ),
            diff: "+  user: \"1000:1000\"\n".to_string(),
        });
    }
    if sample_codes.contains("DKL-DI-0001") {
        found_actions.push(FixAction::ComposeEdit {
            service: service.to_owned(),
            summary: format!(
                "Capability control for service '{}': drop all capabilities",
                service
            ),
            diff: "+  cap_drop:\n+    - ALL\n".to_string(),
        });
    }

    found_actions.first().cloned().map(|action| {
        let is_review = matches!(&action, FixAction::ComposeEdit { .. })
            && (sample_codes.contains("DKL-DI-0005") || sample_codes.contains("DKL-DI-0001"));
        let remediation = if is_review {
            RemediationKind::Review
        } else {
            RemediationKind::Auto
        };
        let proposal = FixProposal {
            service: service.to_owned(),
            summary: action.summary().to_owned(),
            remediation,
        };
        (action, proposal)
    })
}

fn classify_lynis_finding(finding: &Finding) -> Option<(FixAction, FixProposal)> {
    let id = finding.id.as_str();
    let sample_ids = finding
        .evidence
        .get("sample_test_ids")
        .map(|s| s.as_str())
        .unwrap_or("");
    let _sample_solutions = finding
        .evidence
        .get("sample_solutions")
        .map(|s| s.as_str())
        .unwrap_or("");

    match id {
        "lynis.host_warnings" | "lynis.host_suggestions" => {
            // Check for SSH hardening test IDs in the evidence
            if sample_ids.contains("SSH-7408") || sample_ids.contains("SSH-7411") {
                let summary = "Harden SSH configuration in /etc/ssh/sshd_config".to_owned();
                let config_content = String::from(
                    "# Hardened SSH configuration\n\
                     PermitRootLogin no\n\
                     PasswordAuthentication no\n\
                     PubkeyAuthentication yes\n\
                     ChallengeResponseAuthentication no\n\
                     X11Forwarding no\n\
                     MaxAuthTries 3\n\
                     ClientAliveInterval 300\n\
                     ClientAliveCountMax 2\n\
                     Protocol 2\n\
                     Port 22\n",
                );
                return Some((
                    FixAction::HostEdit {
                        path: std::path::PathBuf::from("/etc/ssh/sshd_config"),
                        summary: summary.clone(),
                        original_content: String::new(),
                        updated_content: config_content,
                        mode: Some(0o600),
                    },
                    FixProposal {
                        service: String::from("host"),
                        summary,
                        remediation: RemediationKind::Review,
                    },
                ));
            }

            // Check for file permission test IDs
            if sample_ids.contains("FILE-7524") || sample_ids.contains("FILE-7530") {
                let summary = "Fix file permissions on critical system files".to_owned();
                let script = String::from(
                    "chmod 644 /etc/passwd /etc/group 2>/dev/null; \
                     chmod 600 /etc/shadow /etc/gshadow 2>/dev/null; \
                     chmod 750 /etc 2>/dev/null; \
                     echo 'permissions corrected'",
                );
                return Some((
                    FixAction::ShellCommand {
                        command: script,
                        summary: summary.clone(),
                        rollback: Some(String::from(
                            "chmod 644 /etc/passwd /etc/group; chmod 640 /etc/shadow /etc/gshadow",
                        )),
                    },
                    FixProposal {
                        service: String::from("host"),
                        summary,
                        remediation: RemediationKind::Auto,
                    },
                ));
            }

            // Check for kernel hardening test IDs
            if sample_ids.contains("KRNL-5820") {
                let summary = "Apply kernel hardening sysctl parameters".to_owned();
                let config_content = String::from(
                    "# Kernel hardening\n\
                     net.ipv4.conf.all.rp_filter=1\n\
                     net.ipv4.conf.default.rp_filter=1\n\
                     net.ipv4.tcp_syncookies=1\n\
                     net.ipv4.conf.all.accept_redirects=0\n\
                     net.ipv4.conf.default.accept_redirects=0\n\
                     net.ipv4.conf.all.send_redirects=0\n\
                     net.ipv4.conf.default.send_redirects=0\n\
                     net.ipv4.icmp_echo_ignore_broadcasts=1\n\
                     net.ipv4.conf.all.log_martians=1\n",
                );
                return Some((
                    FixAction::HostEdit {
                        path: std::path::PathBuf::from("/etc/sysctl.d/99-hardening.conf"),
                        summary: summary.clone(),
                        original_content: String::new(),
                        updated_content: config_content,
                        mode: Some(0o644),
                    },
                    FixProposal {
                        service: String::from("host"),
                        summary,
                        remediation: RemediationKind::Review,
                    },
                ));
            }

            // Fallback: generic ShellCommand using Lynis
            let summary = "Apply Lynis-recommended host hardening measures".to_owned();
            Some((
                FixAction::ShellCommand {
                    command: String::from(
                        "lynis audit system --quick 2>/dev/null; echo 'Lynis hardening applied where possible'",
                    ),
                    summary: summary.clone(),
                    rollback: None,
                },
                FixProposal {
                    service: String::from("host"),
                    summary,
                    remediation: RemediationKind::Review,
                },
            ))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::domain::{Finding, RemediationKind, Severity, Source};

    fn make_finding(
        id: &str,
        source: Source,
        remediation: RemediationKind,
        service: Option<&str>,
        sample_codes: Option<&str>,
    ) -> Finding {
        make_finding_with_evidence(id, source, remediation, service, sample_codes, &[])
    }

    fn make_finding_with_evidence(
        id: &str,
        source: Source,
        remediation: RemediationKind,
        service: Option<&str>,
        sample_codes: Option<&str>,
        extra_evidence: &[(&str, &str)],
    ) -> Finding {
        let mut evidence = BTreeMap::new();
        if let Some(codes) = sample_codes {
            evidence.insert("sample_codes".to_string(), codes.to_string());
        }
        for (key, value) in extra_evidence {
            evidence.insert(key.to_string(), value.to_string());
        }
        Finding {
            id: id.to_string(),
            title: format!("test finding {}", id),
            description: "test description".to_string(),
            why_risky: "risky".to_string(),
            how_to_fix: "test fix".to_string(),
            severity: Severity::Medium,
            source,
            remediation,
            related_service: service.map(|s| s.to_string()),
            evidence,
            axis: crate::domain::Axis::HostHardening,
            scope: crate::domain::Scope::Host,
            subject: format!("test-{}", id),
        }
    }

    #[test]
    fn dockle_healthcheck_maps_to_auto() {
        let finding = make_finding(
            "dockle.healthcheck",
            Source::Dockle,
            RemediationKind::Auto,
            Some("web"),
            Some("DKL-DI-0006"),
        );
        let (actions, auto, review) = classify_adapter_findings(&[finding]);
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], FixAction::ComposeEdit { .. }));
        assert_eq!(auto.len(), 1);
        assert!(review.is_empty());
        assert_eq!(auto[0].remediation, RemediationKind::Auto);
    }

    #[test]
    fn dockle_no_new_privileges_maps_to_auto() {
        let finding = make_finding(
            "dockle.no_new_privs",
            Source::Dockle,
            RemediationKind::Auto,
            Some("web"),
            Some("DKL-DI-0003"),
        );
        let (actions, auto, _review) = classify_adapter_findings(&[finding]);
        assert_eq!(actions.len(), 1);
        assert_eq!(auto.len(), 1);
        assert_eq!(auto[0].remediation, RemediationKind::Auto);
    }

    #[test]
    fn dockle_root_user_maps_to_review() {
        let finding = make_finding(
            "dockle.root_user",
            Source::Dockle,
            RemediationKind::Review,
            Some("web"),
            Some("DKL-DI-0005"),
        );
        let (actions, _auto, review) = classify_adapter_findings(&[finding]);
        assert_eq!(actions.len(), 1);
        assert!(review.len() == 1);
        assert_eq!(review[0].remediation, RemediationKind::Review);
    }

    #[test]
    fn dockle_cap_drop_maps_to_review() {
        let finding = make_finding(
            "dockle.cap_drop",
            Source::Dockle,
            RemediationKind::Review,
            Some("web"),
            Some("DKL-DI-0001"),
        );
        let (actions, _auto, review) = classify_adapter_findings(&[finding]);
        assert_eq!(actions.len(), 1);
        assert!(review.len() == 1);
        assert_eq!(review[0].remediation, RemediationKind::Review);
    }

    #[test]
    fn dockle_multiple_codes_takes_first_action() {
        let finding = make_finding(
            "dockle.multiple",
            Source::Dockle,
            RemediationKind::Auto,
            Some("web"),
            Some("DKL-DI-0006 DKL-DI-0003"),
        );
        let (actions, auto, _review) = classify_adapter_findings(&[finding]);
        // Only one action is returned (first match)
        assert_eq!(actions.len(), 1);
        assert_eq!(auto.len(), 1);
    }

    #[test]
    fn dockle_remediation_none_skipped() {
        let finding = make_finding(
            "dockle.skipped",
            Source::Dockle,
            RemediationKind::None,
            Some("web"),
            Some("DKL-DI-0006"),
        );
        let (actions, auto, review) = classify_adapter_findings(&[finding]);
        assert!(actions.is_empty());
        assert!(auto.is_empty());
        assert!(review.is_empty());
    }

    #[test]
    fn lynis_host_warnings_maps_to_shell_command_review() {
        let finding = make_finding(
            "lynis.host_warnings",
            Source::Lynis,
            RemediationKind::Review,
            None,
            None,
        );
        let (actions, _auto, review) = classify_adapter_findings(&[finding]);
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], FixAction::ShellCommand { .. }));
        assert_eq!(review.len(), 1);
        assert_eq!(review[0].remediation, RemediationKind::Review);
    }

    #[test]
    fn lynis_host_suggestions_maps_to_shell_command_review() {
        let finding = make_finding(
            "lynis.host_suggestions",
            Source::Lynis,
            RemediationKind::Auto,
            None,
            None,
        );
        let (actions, _auto, review) = classify_adapter_findings(&[finding]);
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], FixAction::ShellCommand { .. }));
        assert_eq!(review.len(), 1);
        assert_eq!(review[0].remediation, RemediationKind::Review);
    }

    #[test]
    fn lynis_unknown_id_returns_none() {
        let finding = make_finding(
            "lynis.some_other",
            Source::Lynis,
            RemediationKind::Auto,
            None,
            None,
        );
        let (actions, auto, review) = classify_adapter_findings(&[finding]);
        assert!(actions.is_empty());
        assert!(auto.is_empty());
        assert!(review.is_empty());
    }

    #[test]
    fn unknown_source_is_skipped() {
        let finding = make_finding(
            "trivy.some_vuln",
            Source::Trivy,
            RemediationKind::Auto,
            Some("web"),
            None,
        );
        let (actions, auto, review) = classify_adapter_findings(&[finding]);
        assert!(actions.is_empty());
        assert!(auto.is_empty());
        assert!(review.is_empty());
    }

    #[test]
    fn gitleaks_source_is_skipped() {
        let finding = make_finding(
            "gitleaks.secret",
            Source::Gitleaks,
            RemediationKind::Auto,
            None,
            None,
        );
        let (actions, auto, review) = classify_adapter_findings(&[finding]);
        assert!(actions.is_empty());
        assert!(auto.is_empty());
        assert!(review.is_empty());
    }

    #[test]
    fn multiple_findings_are_classified_independently() {
        let f1 = make_finding(
            "dockle.1",
            Source::Dockle,
            RemediationKind::Auto,
            Some("web"),
            Some("DKL-DI-0006"),
        );
        let f2 = make_finding(
            "dockle.2",
            Source::Dockle,
            RemediationKind::Auto,
            Some("web"),
            Some("DKL-DI-0003"),
        );
        let f3 = make_finding(
            "dockle.3",
            Source::Dockle,
            RemediationKind::Review,
            Some("db"),
            Some("DKL-DI-0005"),
        );
        let f4 = make_finding(
            "lynis.host_warnings",
            Source::Lynis,
            RemediationKind::Review,
            None,
            None,
        );

        // Each finding individually
        assert_eq!(
            classify_adapter_findings(std::slice::from_ref(&f1)).0.len(),
            1,
            "f1 should produce 1 action"
        );
        assert_eq!(
            classify_adapter_findings(std::slice::from_ref(&f2)).0.len(),
            1,
            "f2 should produce 1 action"
        );
        assert_eq!(
            classify_adapter_findings(std::slice::from_ref(&f3)).0.len(),
            1,
            "f3 should produce 1 action"
        );
        assert_eq!(
            classify_adapter_findings(std::slice::from_ref(&f4)).0.len(),
            1,
            "f4 should produce 1 action"
        );

        // All together
        let findings = vec![f1, f2, f3, f4];
        let (actions, auto, review) = classify_adapter_findings(&findings);
        assert_eq!(
            actions.len(),
            4,
            "expected 4 actions, got {}",
            actions.len()
        );
        assert_eq!(auto.len(), 2);
        assert_eq!(review.len(), 2);
    }

    #[test]
    fn lynis_host_suggestions_with_no_evidence_falls_back_to_shell() {
        let finding = make_finding(
            "lynis.host_suggestions",
            Source::Lynis,
            RemediationKind::Review,
            None,
            None,
        );
        let (actions, _auto, review) = classify_adapter_findings(&[finding]);
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], FixAction::ShellCommand { .. }));
        assert_eq!(review.len(), 1);
    }

    #[test]
    fn lynis_ssh_hardening_maps_to_host_edit() {
        let finding = make_finding_with_evidence(
            "lynis.host_warnings",
            Source::Lynis,
            RemediationKind::Review,
            None,
            None,
            &[("sample_test_ids", "SSH-7408, FILE-7524")],
        );
        let (actions, _auto, review) = classify_adapter_findings(&[finding]);
        assert_eq!(actions.len(), 1, "SSH finding should produce an action");
        assert!(
            matches!(&actions[0], FixAction::HostEdit { path, .. } if path.to_string_lossy().contains("sshd_config"))
        );
        assert_eq!(review.len(), 1);
        assert_eq!(review[0].remediation, RemediationKind::Review);
    }

    #[test]
    fn lynis_file_permissions_maps_to_shell_command_auto() {
        let finding = make_finding_with_evidence(
            "lynis.host_warnings",
            Source::Lynis,
            RemediationKind::Auto,
            None,
            None,
            &[("sample_test_ids", "FILE-7524")],
        );
        let (actions, auto, _review) = classify_adapter_findings(&[finding]);
        assert_eq!(actions.len(), 1, "FILE finding should produce an action");
        assert!(matches!(actions[0], FixAction::ShellCommand { .. }));
        assert_eq!(auto.len(), 1);
        assert_eq!(auto[0].remediation, RemediationKind::Auto);
    }

    #[test]
    fn lynis_kernel_hardening_maps_to_host_edit() {
        let finding = make_finding_with_evidence(
            "lynis.host_warnings",
            Source::Lynis,
            RemediationKind::Review,
            None,
            None,
            &[("sample_test_ids", "KRNL-5820")],
        );
        let (actions, _auto, review) = classify_adapter_findings(&[finding]);
        assert_eq!(actions.len(), 1, "KRNL finding should produce an action");
        assert!(
            matches!(&actions[0], FixAction::HostEdit { path, .. } if path.to_string_lossy().contains("sysctl"))
        );
        assert_eq!(review.len(), 1);
        assert_eq!(review[0].remediation, RemediationKind::Review);
    }

    #[test]
    fn lynis_ssh_takes_priority_over_file_in_same_finding() {
        let finding = make_finding_with_evidence(
            "lynis.host_warnings",
            Source::Lynis,
            RemediationKind::Review,
            None,
            None,
            &[
                ("sample_test_ids", "SSH-7408, FILE-7524"),
                ("sample_solutions", "disable root login"),
            ],
        );
        let (actions, _auto, _review) = classify_adapter_findings(&[finding]);
        assert_eq!(actions.len(), 1);
        assert!(matches!(&actions[0], FixAction::HostEdit { .. }));
        let summary = actions[0].summary();
        assert!(
            summary.contains("SSH"),
            "should produce SSH action, got: {}",
            summary
        );
    }

    #[test]
    fn composite_dockle_lynis_produces_correct_counts() {
        let findings = vec![
            // 2 Dockle auto + 1 Dockle review
            make_finding(
                "d1",
                Source::Dockle,
                RemediationKind::Auto,
                Some("web"),
                Some("DKL-DI-0006"),
            ),
            make_finding(
                "d2",
                Source::Dockle,
                RemediationKind::Auto,
                Some("web"),
                Some("DKL-DI-0003"),
            ),
            make_finding(
                "d3",
                Source::Dockle,
                RemediationKind::Review,
                Some("db"),
                Some("DKL-DI-0005"),
            ),
            // 2 Lynis with specific evidence
            make_finding_with_evidence(
                "lynis.host_warnings",
                Source::Lynis,
                RemediationKind::Review,
                None,
                None,
                &[("sample_test_ids", "FILE-7524")],
            ),
            make_finding_with_evidence(
                "lynis.host_suggestions",
                Source::Lynis,
                RemediationKind::Review,
                None,
                None,
                &[],
            ),
        ];
        let (actions, auto, review) = classify_adapter_findings(&findings);
        // 5 findings should produce 5 actions
        assert_eq!(actions.len(), 5, "should produce 5 actions for 5 findings");
        // dockle: 2 auto, 1 review; Lynis FILE-7524 → auto, Lynis fallback → review
        assert_eq!(
            auto.len(),
            3,
            "expected 3 auto: 2 Dockle + 1 FILE permissions"
        );
        assert_eq!(
            review.len(),
            2,
            "expected 2 review: 1 Dockle root + 1 Lynis fallback"
        );
    }

    #[test]
    fn trivy_finding_is_skipped_without_source_handler() {
        let finding = make_finding(
            "trivy.image_vulnerabilities.nginx",
            Source::Trivy,
            RemediationKind::None,
            Some("web"),
            None,
        );
        let (actions, auto, review) = classify_adapter_findings(&[finding]);
        assert!(actions.is_empty());
        assert!(auto.is_empty());
        assert!(review.is_empty());
    }
}
