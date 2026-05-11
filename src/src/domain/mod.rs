use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Axis {
    SensitiveData,
    ExcessivePermissions,
    UnnecessaryExposure,
    UpdateSupplyChainRisk,
    HostHardening,
}

impl Axis {
    pub const ALL: [Self; 5] = [
        Self::SensitiveData,
        Self::ExcessivePermissions,
        Self::UnnecessaryExposure,
        Self::UpdateSupplyChainRisk,
        Self::HostHardening,
    ];

    pub const fn as_key(self) -> &'static str {
        match self {
            Self::SensitiveData => "sensitive_data",
            Self::ExcessivePermissions => "permissions",
            Self::UnnecessaryExposure => "exposure",
            Self::UpdateSupplyChainRisk => "supply_chain",
            Self::HostHardening => "host_hardening",
        }
    }

    pub fn from_key(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|axis| axis.as_key() == value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    pub const ALL: [Self; 4] = [Self::Critical, Self::High, Self::Medium, Self::Low];

    pub const fn as_key(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }

    pub fn from_key(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|severity| severity.as_key() == value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Service,
    Image,
    Host,
    Project,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    NativeCompose,
    NativeHost,
    Trivy,
    Lynis,
    Dockle,
    Gitleaks,
}

impl Source {
    pub const fn as_key(self) -> &'static str {
        match self {
            Self::NativeCompose => "native_compose",
            Self::NativeHost => "native_host",
            Self::Trivy => "trivy",
            Self::Lynis => "lynis",
            Self::Dockle => "dockle",
            Self::Gitleaks => "gitleaks",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationKind {
    None,
    #[serde(alias = "safe")]
    Auto,
    #[serde(alias = "guided")]
    Review,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub id: String,
    pub axis: Axis,
    pub severity: Severity,
    pub scope: Scope,
    pub source: Source,
    pub subject: String,
    pub related_service: Option<String>,
    pub title: String,
    pub description: String,
    pub why_risky: String,
    pub how_to_fix: String,
    pub evidence: BTreeMap<String, String>,
    pub remediation: RemediationKind,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ScoreReport {
    pub overall: u8,
    pub scan_focus: Vec<Axis>,
    pub axis_scores: BTreeMap<Axis, u8>,
    pub severity_counts: BTreeMap<Severity, usize>,
    pub axis_weights: BTreeMap<Axis, f32>,
    pub severity_deductions: BTreeMap<Severity, u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceSummary {
    pub name: String,
    pub image: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct HostRuntimeInfo {
    pub hostname: Option<String>,
    pub docker_version: Option<String>,
    pub uptime: Option<String>,
    pub load_average: Option<String>,
    pub fail2ban: DefensiveControlStatus,
    pub fail2ban_jails: Option<usize>,
    pub fail2ban_banned_ips: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DefensiveControlStatus {
    #[default]
    NotDetected,
    Installed,
    Enabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ScanMode {
    #[default]
    Explicit,
    Live,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", content = "detail", rename_all = "snake_case")]
pub enum DockerDiscoveryStatus {
    Available,
    Missing,
    PermissionDenied,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct DiscoveredProjectSummary {
    pub name: String,
    pub source: String,
    pub compose_path: Option<PathBuf>,
    pub working_dir: Option<PathBuf>,
    pub service_count: usize,
}

impl Default for ScoreReport {
    fn default() -> Self {
        let severity_counts = Severity::ALL
            .into_iter()
            .map(|severity| (severity, 0))
            .collect();

        Self {
            overall: 100,
            scan_focus: Vec::new(),
            axis_scores: BTreeMap::new(),
            severity_counts,
            axis_weights: BTreeMap::new(),
            severity_deductions: Severity::ALL
                .into_iter()
                .map(|severity| (severity, 0))
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", content = "detail", rename_all = "snake_case")]
pub enum AdapterStatus {
    Pending,
    Available,
    Missing,
    Skipped(String),
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct ScanMetadata {
    pub scan_mode: ScanMode,
    pub compose_root: Option<PathBuf>,
    pub compose_file: Option<PathBuf>,
    pub host_root: Option<PathBuf>,
    pub host_runtime: Option<HostRuntimeInfo>,
    pub loaded_files: Vec<PathBuf>,
    pub service_count: usize,
    pub services: Vec<ServiceSummary>,
    pub discovered_projects: Vec<DiscoveredProjectSummary>,
    pub docker_status: Option<DockerDiscoveryStatus>,
    pub warnings: Vec<String>,
    pub adapters: BTreeMap<String, AdapterStatus>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize)]
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub score_report: ScoreReport,
    pub metadata: ScanMetadata,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn axis_roundtrip_from_key() {
        for axis in Axis::ALL {
            assert_eq!(Axis::from_key(axis.as_key()), Some(axis));
        }
    }

    #[test]
    fn axis_from_key_returns_none_for_unknown() {
        assert_eq!(Axis::from_key("unknown"), None);
    }

    #[test]
    fn severity_roundtrip_from_key() {
        for severity in Severity::ALL {
            assert_eq!(Severity::from_key(severity.as_key()), Some(severity));
        }
    }

    #[test]
    fn severity_from_key_returns_none_for_unknown() {
        assert_eq!(Severity::from_key("info"), None);
    }

    #[test]
    fn severity_all_variants_have_distinct_keys() {
        let mut keys = std::collections::HashSet::new();
        for severity in Severity::ALL {
            assert!(keys.insert(severity.as_key()));
        }
        assert_eq!(keys.len(), Severity::ALL.len());
    }

    #[test]
    fn finding_constructed_with_minimal_fields() {
        let finding = Finding {
            id: String::from("test.finding"),
            axis: Axis::ExcessivePermissions,
            severity: Severity::High,
            scope: Scope::Service,
            source: Source::NativeCompose,
            subject: String::from("svc"),
            related_service: None,
            title: String::from("title"),
            description: String::from("desc"),
            why_risky: String::from("why"),
            how_to_fix: String::from("fix"),
            evidence: BTreeMap::new(),
            remediation: RemediationKind::Auto,
        };
        assert_eq!(finding.id, "test.finding");
        assert_eq!(finding.axis, Axis::ExcessivePermissions);
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.remediation, RemediationKind::Auto);
    }

    #[test]
    fn scan_result_default_is_empty() {
        let result = ScanResult::default();
        assert!(result.findings.is_empty());
        assert_eq!(result.score_report.overall, 100);
    }

    #[test]
    fn remediation_kind_all_variants() {
        let _ = RemediationKind::None;
        let _ = RemediationKind::Auto;
        let _ = RemediationKind::Review;
    }

    #[test]
    fn scope_all_variants() {
        let _ = Scope::Service;
        let _ = Scope::Image;
        let _ = Scope::Host;
        let _ = Scope::Project;
    }

    #[test]
    fn source_all_variants() {
        let _ = Source::NativeCompose;
        let _ = Source::NativeHost;
        let _ = Source::Trivy;
        let _ = Source::Dockle;
        let _ = Source::Lynis;
        let _ = Source::Gitleaks;
    }
}
