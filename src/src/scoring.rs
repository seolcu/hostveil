use std::collections::BTreeMap;

use crate::domain::{Axis, Finding, ScoreReport, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Coverage {
    pub compose: bool,
    pub host_hardening: bool,
}

/// Severity penalty table.
///
/// These values are intentionally steep: a single Critical finding drops an
/// axis score from 100 to 25, two Critical findings cap the axis at 0.
/// The spread ensures that severity differences are visible in the final
/// weighted score even after axis weights are applied.
fn severity_penalty(severity: Severity) -> u16 {
    match severity {
        Severity::Critical => 75,
        Severity::High => 35,
        Severity::Medium => 15,
        Severity::Low => 5,
    }
}

/// Coverage-aware axis weights.
///
/// Weights are derived from ADR 0005 and must sum to 1.0 for every
/// `(compose, host_hardening)` combination that is actually used.
///
/// Compose-only (the default scan mode):
/// - SensitiveData        0.35  (highest — data exposure is the core risk)
/// - ExcessivePermissions 0.30  (second — root/privileged containers)
/// - UnnecessaryExposure  0.20  (third — public ports, admin UIs)
/// - UpdateSupplyChainRisk 0.15 (lowest — tag drift, image age)
///
/// Compose + HostHardening:
/// - SensitiveData        0.30
/// - ExcessivePermissions 0.25
/// - UnnecessaryExposure  0.15
/// - UpdateSupplyChainRisk 0.15
/// - HostHardening        0.15  (new axis, equal to exposure/updates)
///
/// Host-only:
/// - HostHardening        1.0
/// - All other axes       0.0
fn axis_weight(axis: Axis, coverage: Coverage) -> f32 {
    match (coverage.compose, coverage.host_hardening, axis) {
        (true, false, Axis::SensitiveData) => 0.35,
        (true, false, Axis::ExcessivePermissions) => 0.30,
        (true, false, Axis::UnnecessaryExposure) => 0.20,
        (true, false, Axis::UpdateSupplyChainRisk) => 0.15,
        (true, false, Axis::HostHardening) => 0.0,
        (true, true, Axis::SensitiveData) => 0.30,
        (true, true, Axis::ExcessivePermissions) => 0.25,
        (true, true, Axis::UnnecessaryExposure) => 0.15,
        (true, true, Axis::UpdateSupplyChainRisk) => 0.15,
        (true, true, Axis::HostHardening) => 0.15,
        (false, true, Axis::HostHardening) => 1.0,
        (false, true, _) => 0.0,
        (false, false, _) => 0.0,
    }
}

pub fn build_score_report(findings: &[Finding]) -> ScoreReport {
    build_score_report_with_coverage(
        findings,
        Coverage {
            compose: true,
            host_hardening: false,
        },
    )
}

pub fn build_score_report_with_coverage(findings: &[Finding], coverage: Coverage) -> ScoreReport {
    let mut axis_penalties = BTreeMap::new();
    let mut severity_counts = BTreeMap::new();

    for axis in Axis::ALL {
        axis_penalties.insert(axis, 0_u16);
    }
    for severity in Severity::ALL {
        severity_counts.insert(severity, 0_usize);
    }

    for finding in findings {
        *axis_penalties.entry(finding.axis).or_insert(0) += severity_penalty(finding.severity);
        *severity_counts.entry(finding.severity).or_insert(0) += 1;
    }

    let mut axis_scores = BTreeMap::new();
    let mut axis_weights = BTreeMap::new();
    let mut weighted = 0.0_f32;

    for axis in Axis::ALL {
        let weight = axis_weight(axis, coverage);
        if weight > 0.0 {
            let penalty = axis_penalties.get(&axis).copied().unwrap_or_default();
            let score = 100_i16 - penalty as i16;
            let score = score.max(0) as u8;
            axis_scores.insert(axis, score);
            axis_weights.insert(axis, weight);
            weighted += score as f32 * weight;
        }
    }

    let overall = if coverage.compose || coverage.host_hardening {
        weighted.round() as u8
    } else {
        100
    };

    let scan_focus = Axis::ALL
        .into_iter()
        .filter(|axis| axis_weight(*axis, coverage) > 0.0)
        .collect();

    ScoreReport {
        overall,
        scan_focus,
        axis_scores,
        severity_counts,
        axis_weights,
        severity_deductions: Severity::ALL
            .into_iter()
            .map(|severity| (severity, severity_penalty(severity)))
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::domain::{Finding, RemediationKind, Scope, Source};

    use super::*;

    fn finding(axis: Axis, severity: Severity, id: &str) -> Finding {
        Finding {
            id: id.to_owned(),
            axis,
            severity,
            scope: Scope::Service,
            source: Source::NativeCompose,
            subject: String::from("svc"),
            related_service: Some(String::from("svc")),
            title: String::from("title"),
            description: String::from("description"),
            why_risky: String::from("why"),
            how_to_fix: String::from("fix"),
            evidence: BTreeMap::new(),
            remediation: RemediationKind::Manual,
        }
    }

    #[test]
    fn counts_findings_by_axis_and_severity() {
        let findings = vec![
            finding(Axis::SensitiveData, Severity::Critical, "a"),
            finding(Axis::UnnecessaryExposure, Severity::High, "b"),
            finding(Axis::UnnecessaryExposure, Severity::Low, "c"),
        ];

        let report = build_score_report(&findings);

        assert_eq!(report.axis_scores[&Axis::SensitiveData], 25);
        assert_eq!(report.axis_scores[&Axis::ExcessivePermissions], 100);
        assert_eq!(report.axis_scores[&Axis::UnnecessaryExposure], 60);
        assert_eq!(report.axis_scores[&Axis::UpdateSupplyChainRisk], 100);
        assert!(!report.axis_scores.contains_key(&Axis::HostHardening));
        assert_eq!(report.severity_counts[&Severity::Critical], 1);
        assert_eq!(report.severity_counts[&Severity::High], 1);
        assert_eq!(report.severity_counts[&Severity::Low], 1);
    }

    #[test]
    fn single_critical_sensitive_finding_tanks_overall_score() {
        let report = build_score_report(&[finding(Axis::SensitiveData, Severity::Critical, "a")]);

        assert_eq!(report.overall, 74);
        assert!(report.overall < 80);
    }

    #[test]
    fn multiple_findings_cap_axis_scores_at_zero() {
        let report = build_score_report(&[
            finding(Axis::ExcessivePermissions, Severity::Critical, "a"),
            finding(Axis::ExcessivePermissions, Severity::Critical, "b"),
        ]);

        assert_eq!(report.axis_scores[&Axis::ExcessivePermissions], 0);
    }

    #[test]
    fn host_hardening_affects_overall_only_when_covered() {
        let findings = [finding(Axis::HostHardening, Severity::Critical, "host")];

        let without_host = build_score_report(&findings);
        let with_host = build_score_report_with_coverage(
            &findings,
            Coverage {
                compose: false,
                host_hardening: true,
            },
        );

        assert_eq!(without_host.overall, 100);
        assert!(!without_host.axis_scores.contains_key(&Axis::HostHardening));
        assert_eq!(with_host.overall, 25);
        assert_eq!(with_host.axis_scores[&Axis::HostHardening], 25);
    }

    fn expected_python_overall(axis_scores: &BTreeMap<Axis, u8>) -> u8 {
        // Mirrors proto/hostveil/scoring.py for Compose-only scans.
        let weighted = axis_scores[&Axis::SensitiveData] as f32 * 0.35
            + axis_scores[&Axis::ExcessivePermissions] as f32 * 0.30
            + axis_scores[&Axis::UnnecessaryExposure] as f32 * 0.20
            + axis_scores[&Axis::UpdateSupplyChainRisk] as f32 * 0.15;
        weighted.round() as u8
    }

    #[test]
    fn matches_python_prototype_for_compose_only_scans() {
        let findings = vec![
            finding(Axis::SensitiveData, Severity::High, "a"),
            finding(Axis::SensitiveData, Severity::Low, "b"),
            finding(Axis::ExcessivePermissions, Severity::Medium, "c"),
            finding(Axis::UnnecessaryExposure, Severity::Critical, "d"),
            finding(Axis::UpdateSupplyChainRisk, Severity::Low, "e"),
        ];

        let report = build_score_report(&findings);

        assert_eq!(report.overall, expected_python_overall(&report.axis_scores));
    }

    #[test]
    fn severe_permissions_drops_score_more_than_low_risk_supply_chain() {
        let low_risk = build_score_report(&[finding(
            Axis::UpdateSupplyChainRisk,
            Severity::Low,
            "supply",
        )]);
        let high_risk = build_score_report(&[finding(
            Axis::ExcessivePermissions,
            Severity::Critical,
            "priv",
        )]);

        assert!(high_risk.overall < low_risk.overall);
    }

    #[test]
    fn weights_sum_to_one_for_known_coverage_modes() {
        let compose_only = Axis::ALL
            .into_iter()
            .map(|axis| {
                axis_weight(
                    axis,
                    Coverage {
                        compose: true,
                        host_hardening: false,
                    },
                )
            })
            .sum::<f32>();
        let compose_and_host = Axis::ALL
            .into_iter()
            .map(|axis| {
                axis_weight(
                    axis,
                    Coverage {
                        compose: true,
                        host_hardening: true,
                    },
                )
            })
            .sum::<f32>();
        let host_only = Axis::ALL
            .into_iter()
            .map(|axis| {
                axis_weight(
                    axis,
                    Coverage {
                        compose: false,
                        host_hardening: true,
                    },
                )
            })
            .sum::<f32>();

        assert!((compose_only - 1.0).abs() < 0.0001);
        assert!((compose_and_host - 1.0).abs() < 0.0001);
        assert!((host_only - 1.0).abs() < 0.0001);
    }

    #[test]
    fn empty_findings_yield_perfect_score() {
        let report = build_score_report(&[]);

        assert_eq!(report.overall, 100);
        for axis in Axis::ALL {
            assert_eq!(
                report.axis_scores.get(&axis).copied().unwrap_or(100),
                100,
                "axis {axis:?} should be 100 with no findings"
            );
        }
    }

    #[test]
    fn multiple_medium_findings_accumulate_and_cap_at_zero() {
        // 7 Medium findings in the same axis: 7 * 15 = 105, capped at 0
        let findings: Vec<Finding> = (0..7)
            .map(|index| {
                finding(
                    Axis::UnnecessaryExposure,
                    Severity::Medium,
                    &format!("f{index}"),
                )
            })
            .collect();
        let report = build_score_report(&findings);

        assert_eq!(report.axis_scores[&Axis::UnnecessaryExposure], 0);
        assert_eq!(report.severity_counts[&Severity::Medium], 7);
    }

    #[test]
    fn critical_composite_scores_lower_than_low_only() {
        // Two Critical findings in high-weight axes
        let critical_composite = build_score_report(&[
            finding(Axis::SensitiveData, Severity::Critical, "secret"),
            finding(Axis::ExcessivePermissions, Severity::Critical, "priv"),
        ]);

        // One Low finding in the lowest-weight axis
        let low_only =
            build_score_report(&[finding(Axis::UpdateSupplyChainRisk, Severity::Low, "tag")]);

        assert!(
            critical_composite.overall < low_only.overall,
            "critical composite ({}) should score lower than low-only ({})",
            critical_composite.overall,
            low_only.overall
        );
    }

    #[test]
    fn host_only_scan_ignores_compose_findings() {
        let findings = [
            finding(Axis::SensitiveData, Severity::Critical, "secret"),
            finding(Axis::HostHardening, Severity::High, "ssh"),
        ];

        let report = build_score_report_with_coverage(
            &findings,
            Coverage {
                compose: false,
                host_hardening: true,
            },
        );

        // Only HostHardening should contribute; SensitiveData is ignored
        assert_eq!(report.overall, 65); // 100 - 35 (High penalty)
        assert_eq!(report.axis_scores[&Axis::HostHardening], 65);
        assert!(!report.axis_scores.contains_key(&Axis::SensitiveData));
    }

    #[test]
    fn coverage_both_enabled_uses_all_axes() {
        let findings = [
            finding(Axis::SensitiveData, Severity::Critical, "secret"),
            finding(Axis::ExcessivePermissions, Severity::High, "mode"),
            finding(Axis::HostHardening, Severity::Medium, "ssh"),
        ];
        let report = build_score_report_with_coverage(
            &findings,
            Coverage {
                compose: true,
                host_hardening: true,
            },
        );
        assert!(report.axis_scores.contains_key(&Axis::SensitiveData));
        assert!(report.axis_scores.contains_key(&Axis::ExcessivePermissions));
        assert!(report.axis_scores.contains_key(&Axis::HostHardening));
        assert_eq!(report.axis_scores.len(), 5); // All 4 compose + 1 host
    }

    #[test]
    fn coverage_all_disabled_returns_empty_scores() {
        let findings = [finding(Axis::SensitiveData, Severity::Critical, "secret")];
        let report = build_score_report_with_coverage(
            &findings,
            Coverage {
                compose: false,
                host_hardening: false,
            },
        );
        assert!(
            report.axis_scores.is_empty(),
            "no coverage = no axis scores"
        );
        assert_eq!(report.overall, 100, "no axes = perfect score");
    }

    #[test]
    fn single_low_penalty_is_seven() {
        let findings = [finding(Axis::HostHardening, Severity::Low, "weak_ssh")];
        let report = build_score_report_with_coverage(
            &findings,
            Coverage {
                compose: false,
                host_hardening: true,
            },
        );
        assert_eq!(report.overall, 95, "Low penalty should be 5");
        assert_eq!(
            report.severity_deductions[&Severity::Low],
            5,
            "Low severity maps to 5 point deduction"
        );
    }

    #[test]
    fn severity_penalty_maps_correctly() {
        assert_eq!(severity_penalty(Severity::Critical), 75);
        assert_eq!(severity_penalty(Severity::High), 35);
        assert_eq!(severity_penalty(Severity::Medium), 15);
        assert_eq!(severity_penalty(Severity::Low), 5);
    }

    #[test]
    fn score_caps_at_zero_with_exactly_100_penalty() {
        let findings = [
            finding(Axis::HostHardening, Severity::High, "high_1"),
            finding(Axis::HostHardening, Severity::High, "high_2"),
            finding(Axis::HostHardening, Severity::High, "high_3"),
            finding(Axis::HostHardening, Severity::High, "high_4"),
            finding(Axis::HostHardening, Severity::High, "high_5"),
            finding(Axis::HostHardening, Severity::High, "high_6"),
            finding(Axis::HostHardening, Severity::High, "high_7"),
            finding(Axis::HostHardening, Severity::High, "high_8"),
            finding(Axis::HostHardening, Severity::High, "high_9"),
            finding(Axis::HostHardening, Severity::High, "high_10"),
        ];
        let report = build_score_report_with_coverage(
            &findings,
            Coverage {
                compose: false,
                host_hardening: true,
            },
        );
        assert_eq!(
            report.overall, 0,
            "10 High findings = 100 penalty, score should be 0"
        );
    }
}
