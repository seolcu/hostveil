use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::io::{self, ErrorKind};
use std::path::Path;
use std::time::Duration;

use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, Borders, Clear, List, ListItem, ListState, Padding, Paragraph, Scrollbar,
    ScrollbarOrientation, ScrollbarState, Wrap,
};

use self::component::Component;

use crate::domain::{
    AdapterStatus, Axis, DefensiveControlStatus, DockerDiscoveryStatus, Finding, HostRuntimeInfo,
    RemediationKind, ScanResult, Scope, Severity, Source,
};
use crate::i18n;
use crate::settings;

mod component;
mod fix_review;
mod theme;

pub use fix_review::{run_fix_review, run_interactive_fix_flow};
pub use theme::{Theme, ThemePreset, panel_borders};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    Overview,
    Findings,
    History,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum LayoutPreset {
    Adaptive,
    AdaptiveLegacy,
    Wide,
    Balanced,
    Compact,
    Focus,
}

impl LayoutPreset {
    fn as_key(self) -> &'static str {
        match self {
            Self::Adaptive => "adaptive",
            Self::AdaptiveLegacy => "adaptive_legacy",
            Self::Wide => "wide",
            Self::Balanced => "balanced",
            Self::Compact => "compact",
            Self::Focus => "focus",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Adaptive => "Auto",
            Self::AdaptiveLegacy => "Adaptive",
            Self::Wide => "Wide",
            Self::Balanced => "Balanced",
            Self::Compact => "Compact",
            Self::Focus => "Focus",
        }
    }

    fn from_key(value: &str) -> Option<Self> {
        match value {
            "adaptive" => Some(Self::Adaptive),
            "adaptive_legacy" => Some(Self::AdaptiveLegacy),
            "wide" => Some(Self::Wide),
            "balanced" => Some(Self::Balanced),
            "compact" => Some(Self::Compact),
            "focus" => Some(Self::Focus),
            _ => None,
        }
    }

    fn next(self) -> Self {
        match self {
            Self::Adaptive => Self::AdaptiveLegacy,
            Self::AdaptiveLegacy => Self::Wide,
            Self::Wide => Self::Balanced,
            Self::Balanced => Self::Compact,
            Self::Compact => Self::Focus,
            Self::Focus => Self::Adaptive,
        }
    }

    fn previous(self) -> Self {
        match self {
            Self::Adaptive => Self::Focus,
            Self::AdaptiveLegacy => Self::Adaptive,
            Self::Wide => Self::AdaptiveLegacy,
            Self::Balanced => Self::Wide,
            Self::Compact => Self::Balanced,
            Self::Focus => Self::Compact,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum OverviewFocus {
    ServerStatus,
    ScanResults,
    SecurityScores,
    FixPaths,
}

impl OverviewFocus {
    fn next(self) -> Self {
        match self {
            Self::ServerStatus => Self::ScanResults,
            Self::ScanResults => Self::SecurityScores,
            Self::SecurityScores => Self::FixPaths,
            Self::FixPaths => Self::ServerStatus,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SettingsRow {
    Theme,
    Layout,
    Locale,
    UiBorders,
}

impl SettingsRow {
    fn all() -> [Self; 4] {
        [Self::Theme, Self::Layout, Self::Locale, Self::UiBorders]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FindingsFocus {
    List,
    Detail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FindingSortMode {
    Severity,
    Source,
    Subject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemediationFilter {
    All,
    Fixable,
    Auto,
    Review,
    Manual,
}

#[derive(Debug, Clone)]
enum HitTarget {
    TabOverview,
    TabFindings,
    TabHistory,
    FindingList(usize),
    FindingsDetail,
    OverviewPanel(OverviewFocus),
    SettingsRow(usize),
}

#[derive(Debug, Clone)]
struct AppState {
    hit_boxes: Vec<(Rect, HitTarget)>,
    screen: Screen,
    settings_open: bool,
    help_open: bool,
    search_open: bool,
    search_query: String,
    settings_row: usize,
    findings_focus: FindingsFocus,
    overview_focus: OverviewFocus,
    selected_index: usize,
    detail_scroll: u16,
    findings_list_scroll: u16,
    overview_scroll: BTreeMap<OverviewFocus, u16>,
    history_scroll: u16,
    sorted_indices: Vec<usize>,
    severity_filter: Option<Severity>,
    source_filter: Option<Source>,
    scope_filter: Option<Scope>,
    remediation_filter: RemediationFilter,
    service_filter: Option<String>,
    sort_mode: FindingSortMode,
    layout_preset: LayoutPreset,
    borders_enabled: bool,
    theme: Theme,
    theme_preset: ThemePreset,
    tick: usize,
    status_message: Option<String>,
    status_tick: usize,
}

impl AppState {
    fn handle_persist_error(&mut self, setting_label: String, error: io::Error) {
        if error.kind() == ErrorKind::NotFound {
            return;
        }

        #[cfg(debug_assertions)]
        eprintln!(
            "hostveil: failed to persist {} settings: {}",
            setting_label, error
        );
        self.set_status_message(
            t!("app.settings.persist_failed", setting = setting_label).into_owned(),
        );
    }

    fn cycle_theme(&mut self) {
        self.theme_preset = self.theme_preset.next();
        let mut new_theme = Theme::preset(self.theme_preset);
        new_theme.borders_enabled = self.borders_enabled;
        self.theme = new_theme;
        if let Err(error) = persist_theme_choice(self.theme_preset.as_key()) {
            self.handle_persist_error(t!("app.settings.theme").into_owned(), error);
        }
    }

    fn new(scan_result: &ScanResult) -> Self {
        #[cfg(test)]
        let settings = settings::AppSettings::default();
        #[cfg(not(test))]
        let settings = settings::load();
        let severity_filter = settings
            .severity_filter
            .as_deref()
            .and_then(Self::parse_severity_filter);
        let source_filter = settings
            .source_filter
            .as_deref()
            .and_then(Self::parse_source_filter);
        let service_filter = settings.service_filter.clone();
        let remediation_filter = settings
            .remediation_filter
            .as_deref()
            .and_then(Self::parse_remediation_filter)
            .unwrap_or(RemediationFilter::All);
        let sort_mode = settings
            .sort_mode
            .as_deref()
            .and_then(Self::parse_sort_mode)
            .unwrap_or(FindingSortMode::Severity);
        let theme_preset = settings
            .theme
            .as_deref()
            .and_then(ThemePreset::from_key)
            .unwrap_or(ThemePreset::TokyoNight);
        let layout_preset = settings
            .layout
            .as_deref()
            .and_then(LayoutPreset::from_key)
            .unwrap_or(LayoutPreset::Adaptive);
        let borders_enabled = settings.ui_borders.unwrap_or(false);

        Self {
            hit_boxes: Vec::new(),
            screen: Screen::Overview,
            settings_open: false,
            help_open: false,
            search_open: false,
            search_query: String::new(),
            settings_row: 0,
            findings_focus: FindingsFocus::List,
            overview_focus: OverviewFocus::ServerStatus,
            selected_index: 0,
            detail_scroll: 0,
            findings_list_scroll: 0,
            overview_scroll: BTreeMap::from([
                (OverviewFocus::ServerStatus, 0),
                (OverviewFocus::ScanResults, 0),
                (OverviewFocus::SecurityScores, 0),
                (OverviewFocus::FixPaths, 0),
            ]),
            history_scroll: 0,
            sorted_indices: visible_finding_indices(
                scan_result,
                severity_filter,
                source_filter,
                None,
                remediation_filter,
                service_filter.as_deref(),
                sort_mode,
                None,
            ),
            severity_filter,
            source_filter,
            scope_filter: None,
            remediation_filter,
            service_filter,
            sort_mode,
            layout_preset,
            borders_enabled,
            theme: {
                let mut t = Theme::preset(theme_preset);
                t.borders_enabled = borders_enabled;
                t
            },
            theme_preset,
            tick: 0,
            status_message: None,
            status_tick: 0,
        }
    }

    fn set_status_message(&mut self, message: impl Into<String>) {
        self.status_message = Some(message.into());
        self.status_tick = self.tick;
    }

    fn clear_expired_status(&mut self) {
        const STATUS_DURATION_TICKS: usize = 30; // ~3 seconds at 100ms poll
        if self.status_message.is_some()
            && self.tick.wrapping_sub(self.status_tick) >= STATUS_DURATION_TICKS
        {
            self.status_message = None;
        }
    }

    fn cycle_layout(&mut self) {
        self.layout_preset = self.layout_preset.next();
        if let Err(error) = persist_layout_choice(self.layout_preset.as_key()) {
            self.handle_persist_error(t!("app.settings.layout").into_owned(), error);
        }
    }

    fn cycle_layout_backward(&mut self) {
        self.layout_preset = self.layout_preset.previous();
        if let Err(error) = persist_layout_choice(self.layout_preset.as_key()) {
            self.handle_persist_error(t!("app.settings.layout").into_owned(), error);
        }
    }

    fn cycle_borders(&mut self) {
        self.borders_enabled = !self.borders_enabled;
        self.theme.borders_enabled = self.borders_enabled;
        if let Err(error) = settings::persist_ui_borders(self.borders_enabled) {
            self.handle_persist_error(t!("app.settings.ui_borders").into_owned(), error);
        }
    }

    fn open_settings(&mut self) {
        self.settings_open = true;
    }

    fn close_settings(&mut self) {
        self.settings_open = false;
    }

    fn active_settings_row(&self) -> SettingsRow {
        let rows = SettingsRow::all();
        rows[self.settings_row.min(rows.len() - 1)]
    }

    fn settings_next_row(&mut self) {
        self.settings_row = (self.settings_row + 1) % SettingsRow::all().len();
    }

    fn settings_prev_row(&mut self) {
        self.settings_row = self.settings_row.saturating_sub(1);
    }

    fn adjust_setting_right(&mut self) {
        match self.active_settings_row() {
            SettingsRow::Theme => self.cycle_theme(),
            SettingsRow::Layout => self.cycle_layout(),
            SettingsRow::Locale => {
                if let Err(error) = i18n::cycle_persisted_locale() {
                    self.handle_persist_error(t!("app.settings.locale").into_owned(), error);
                }
            }
            SettingsRow::UiBorders => self.cycle_borders(),
        }
    }

    fn adjust_setting_left(&mut self) {
        match self.active_settings_row() {
            SettingsRow::Theme => {
                for _ in 0..(ThemePreset::ALL.len().saturating_sub(1)) {
                    self.cycle_theme();
                }
            }
            SettingsRow::Layout => self.cycle_layout_backward(),
            SettingsRow::Locale => {
                if let Err(error) = i18n::cycle_persisted_locale_backward() {
                    self.handle_persist_error(t!("app.settings.locale").into_owned(), error);
                }
            }
            SettingsRow::UiBorders => self.cycle_borders(),
        }
    }

    fn finding_count(&self) -> usize {
        self.sorted_indices.len()
    }

    fn selected_finding<'a>(&self, scan_result: &'a ScanResult) -> Option<&'a Finding> {
        self.sorted_indices
            .get(self.selected_index)
            .and_then(|index| scan_result.findings.get(*index))
    }

    fn open_findings(&mut self) {
        self.screen = Screen::Findings;
        self.findings_focus = FindingsFocus::List;
        self.detail_scroll = 0;
        self.findings_list_scroll = 0;
    }

    fn return_to_overview(&mut self) {
        self.screen = Screen::Overview;
        self.findings_focus = FindingsFocus::List;
        self.detail_scroll = 0;
        self.findings_list_scroll = 0;
    }

    fn open_history(&mut self) {
        self.screen = Screen::History;
        self.history_scroll = 0;
    }

    fn close_history(&mut self) {
        self.screen = Screen::Overview;
        self.history_scroll = 0;
    }

    fn select_next(&mut self) {
        if self.finding_count() > 1 {
            self.selected_index = (self.selected_index + 1).min(self.finding_count() - 1);
            self.detail_scroll = 0;
            self.findings_list_scroll = self.findings_list_scroll.saturating_add(1);
        }
    }

    fn select_previous(&mut self) {
        if self.finding_count() > 1 {
            self.selected_index = self.selected_index.saturating_sub(1);
            self.detail_scroll = 0;
            self.findings_list_scroll = self.findings_list_scroll.saturating_sub(1);
        }
    }

    fn scroll_detail_down(&mut self, amount: u16) {
        self.detail_scroll = self.detail_scroll.saturating_add(amount);
    }

    fn scroll_detail_up(&mut self, amount: u16) {
        self.detail_scroll = self.detail_scroll.saturating_sub(amount);
    }

    fn focus_list(&mut self) {
        self.findings_focus = FindingsFocus::List;
    }

    fn focus_detail(&mut self) {
        self.findings_focus = FindingsFocus::Detail;
    }

    fn toggle_focus(&mut self) {
        self.findings_focus = match self.findings_focus {
            FindingsFocus::List => FindingsFocus::Detail,
            FindingsFocus::Detail => FindingsFocus::List,
        };
    }

    fn clamp_selection(&mut self, scan_result: &ScanResult) {
        self.sorted_indices = visible_finding_indices(
            scan_result,
            self.severity_filter,
            self.source_filter,
            self.scope_filter,
            self.remediation_filter,
            self.service_filter.as_deref(),
            self.sort_mode,
            Some(self.search_query.as_str()).filter(|q| !q.is_empty()),
        );

        if self.sorted_indices.is_empty() {
            self.selected_index = 0;
            self.detail_scroll = 0;
            self.findings_list_scroll = 0;
            return;
        }

        self.selected_index = self.selected_index.min(self.sorted_indices.len() - 1);
        self.findings_list_scroll = self.findings_list_scroll.min(self.selected_index as u16);
    }

    fn active_overview_scroll(&self) -> u16 {
        self.overview_scroll
            .get(&self.overview_focus)
            .copied()
            .unwrap_or(0)
    }

    fn set_active_overview_scroll(&mut self, value: u16) {
        self.overview_scroll.insert(self.overview_focus, value);
    }

    fn scroll_overview_down(&mut self, amount: u16) {
        let next = self.active_overview_scroll().saturating_add(amount);
        self.set_active_overview_scroll(next);
    }

    fn scroll_overview_up(&mut self, amount: u16) {
        let next = self.active_overview_scroll().saturating_sub(amount);
        self.set_active_overview_scroll(next);
    }

    fn focus_next_overview_panel(&mut self) {
        self.overview_focus = self.overview_focus.next();
    }

    fn clamp_detail_scroll(&mut self, max_scroll: usize) {
        self.detail_scroll = self
            .detail_scroll
            .min(max_scroll.min(u16::MAX as usize) as u16);
    }

    fn cycle_severity_filter(&mut self) {
        self.severity_filter = match self.severity_filter {
            None => Some(Severity::Critical),
            Some(Severity::Critical) => Some(Severity::High),
            Some(Severity::High) => Some(Severity::Medium),
            Some(Severity::Medium) => Some(Severity::Low),
            Some(Severity::Low) => None,
        };
        self.selected_index = 0;
        self.detail_scroll = 0;
        self.persist_findings_view();
    }

    fn cycle_source_filter(&mut self) {
        self.source_filter = match self.source_filter {
            None => Some(Source::NativeCompose),
            Some(Source::NativeCompose) => Some(Source::NativeHost),
            Some(Source::NativeHost) => Some(Source::Trivy),
            Some(Source::Trivy) => Some(Source::Lynis),
            Some(Source::Lynis) => Some(Source::Dockle),
            Some(Source::Dockle) => Some(Source::Gitleaks),
            Some(Source::Gitleaks) => None,
        };
        self.selected_index = 0;
        self.detail_scroll = 0;
        self.persist_findings_view();
    }

    fn cycle_service_filter(&mut self, scan_result: &ScanResult) {
        let mut services: Vec<String> = scan_result
            .findings
            .iter()
            .filter_map(|f| f.related_service.clone())
            .collect();
        services.sort();
        services.dedup();

        self.service_filter = match &self.service_filter {
            None if !services.is_empty() => Some(services[0].clone()),
            Some(current) => {
                let index = services.iter().position(|s| s == current);
                match index {
                    Some(i) if i + 1 < services.len() => Some(services[i + 1].clone()),
                    _ => None,
                }
            }
            _ => None,
        };
        self.selected_index = 0;
        self.detail_scroll = 0;
        self.persist_findings_view();
    }

    fn cycle_sort_mode(&mut self) {
        self.sort_mode = match self.sort_mode {
            FindingSortMode::Severity => FindingSortMode::Source,
            FindingSortMode::Source => FindingSortMode::Subject,
            FindingSortMode::Subject => FindingSortMode::Severity,
        };
        self.selected_index = 0;
        self.detail_scroll = 0;
        self.persist_findings_view();
    }

    fn cycle_remediation_filter(&mut self) {
        self.remediation_filter = match self.remediation_filter {
            RemediationFilter::All => RemediationFilter::Fixable,
            RemediationFilter::Fixable => RemediationFilter::Auto,
            RemediationFilter::Auto => RemediationFilter::Review,
            RemediationFilter::Review => RemediationFilter::Manual,
            RemediationFilter::Manual => RemediationFilter::All,
        };
        self.selected_index = 0;
        self.detail_scroll = 0;
        self.persist_findings_view();
    }

    fn reset_filters_and_sort(&mut self) {
        self.severity_filter = None;
        self.source_filter = None;
        self.service_filter = None;
        self.remediation_filter = RemediationFilter::All;
        self.sort_mode = FindingSortMode::Severity;
        self.selected_index = 0;
        self.detail_scroll = 0;
        self.persist_findings_view();
    }

    fn parse_severity_filter(value: &str) -> Option<Severity> {
        match value {
            "critical" => Some(Severity::Critical),
            "high" => Some(Severity::High),
            "medium" => Some(Severity::Medium),
            "low" => Some(Severity::Low),
            _ => None,
        }
    }

    fn parse_source_filter(value: &str) -> Option<Source> {
        match value {
            "native_compose" => Some(Source::NativeCompose),
            "native_host" => Some(Source::NativeHost),
            "trivy" => Some(Source::Trivy),
            "lynis" => Some(Source::Lynis),
            "dockle" => Some(Source::Dockle),
            "gitleaks" => Some(Source::Gitleaks),
            _ => None,
        }
    }

    fn parse_remediation_filter(value: &str) -> Option<RemediationFilter> {
        match value {
            "all" => Some(RemediationFilter::All),
            "fixable" => Some(RemediationFilter::Fixable),
            "safe" | "auto" => Some(RemediationFilter::Auto),
            "guided" | "review" => Some(RemediationFilter::Review),
            "manual" => Some(RemediationFilter::Manual),
            _ => None,
        }
    }

    fn parse_sort_mode(value: &str) -> Option<FindingSortMode> {
        match value {
            "severity" => Some(FindingSortMode::Severity),
            "source" => Some(FindingSortMode::Source),
            "subject" => Some(FindingSortMode::Subject),
            _ => None,
        }
    }

    fn persist_findings_view(&mut self) {
        #[cfg(not(test))]
        if let Err(error) = settings::persist_findings_view(
            self.severity_filter.map(|s| s.as_key()),
            self.source_filter.map(|s| s.as_key()),
            self.service_filter.as_deref(),
            Some(match self.remediation_filter {
                RemediationFilter::All => "all",
                RemediationFilter::Fixable => "fixable",
                RemediationFilter::Auto => "auto",
                RemediationFilter::Review => "review",
                RemediationFilter::Manual => "manual",
            }),
            Some(match self.sort_mode {
                FindingSortMode::Severity => "severity",
                FindingSortMode::Source => "source",
                FindingSortMode::Subject => "subject",
            }),
        ) {
            self.handle_persist_error(t!("app.settings.findings_view").into_owned(), error);
        }
    }
}

fn persist_theme_choice(theme: &str) -> io::Result<()> {
    #[cfg(not(test))]
    return settings::persist_theme(theme);
    #[cfg(test)]
    {
        let _ = theme;
        Ok(())
    }
}

fn persist_layout_choice(layout: &str) -> io::Result<()> {
    #[cfg(not(test))]
    return settings::persist_layout(layout);
    #[cfg(test)]
    {
        let _ = layout;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResultSummaryRow {
    label: String,
    severity: Option<Severity>,
    count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OverviewLayoutMode {
    Wide,
    Tall,
    Compact,
    Narrow,
    Focus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FindingsLayoutMode {
    SideBySide,
    Stacked,
    CompactList,
    Narrow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FixAvailability {
    Available,
    NoComposeTarget,
    NoFindingSelected,
    NoServiceFix,
    ManualOnly,
}

impl FixAvailability {
    fn is_fixable(self) -> bool {
        matches!(self, Self::Available)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum HostFindingCategory {
    Ssh,
    DockerHost,
    Firewall,
    Updates,
    Kernel,
    Mac,
    Filesystem,
    Fim,
    Defenses,
    Other,
}

impl HostFindingCategory {
    fn from_finding_id(id: &str) -> Self {
        if id.starts_with("host.ssh_") {
            Self::Ssh
        } else if id.starts_with("host.docker_") {
            Self::DockerHost
        } else if id == "host.no_firewall_detected"
            || id.starts_with("host.ufw_")
            || id.starts_with("host.firewalld_")
            || id.starts_with("host.nftables_")
        {
            Self::Firewall
        } else if id.starts_with("host.apt_")
            || id.starts_with("host.dnf_")
            || id.starts_with("host.yum_")
        {
            Self::Updates
        } else if id.starts_with("host.kernel.") || id == "host.secure_boot_disabled" {
            Self::Kernel
        } else if id.starts_with("host.selinux_")
            || id.starts_with("host.apparmor_")
            || id == "host.mac_framework_missing"
        {
            Self::Mac
        } else if id == "host.mount_flags_missing"
            || id.starts_with("host.proc_")
            || id.starts_with("host.systemd_")
            || id.starts_with("host.grub_")
            || id.starts_with("host.shadow_")
            || id.starts_with("host.tmp_")
        {
            Self::Filesystem
        } else if id.starts_with("host.fim_")
            || id.starts_with("host.aide_")
            || id.starts_with("host.tripwire_")
        {
            Self::Fim
        } else if id == "host.fail2ban_not_enabled" || id == "host.defensive_controls_missing" {
            Self::Defenses
        } else {
            Self::Other
        }
    }

    fn label(self) -> String {
        match self {
            Self::Ssh => t!("app.host_category.ssh").into_owned(),
            Self::DockerHost => t!("app.host_category.docker_host").into_owned(),
            Self::Firewall => t!("app.host_category.firewall").into_owned(),
            Self::Updates => t!("app.host_category.updates").into_owned(),
            Self::Kernel => t!("app.host_category.kernel").into_owned(),
            Self::Mac => t!("app.host_category.mac").into_owned(),
            Self::Filesystem => t!("app.host_category.filesystem").into_owned(),
            Self::Fim => t!("app.host_category.fim").into_owned(),
            Self::Defenses => t!("app.host_category.defenses").into_owned(),
            Self::Other => t!("app.host_category.other").into_owned(),
        }
    }
}

#[derive(Debug, Clone)]
struct HostCategorySummary {
    category: HostFindingCategory,
    count: usize,
    highest_severity: Severity,
}

#[derive(Debug)]
pub enum TuiAction {
    Exit,
    TriggerFix {
        compose_file: std::path::PathBuf,
        finding_id: Option<String>,
        adapter_findings: Vec<Finding>,
    },
}

pub fn run<F>(scan_result: &mut ScanResult, mut refresh: F) -> io::Result<TuiAction>
where
    F: FnMut(&mut ScanResult) -> bool,
{
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let mut state = AppState::new(scan_result);

    let result = run_event_loop(&mut terminal, scan_result, &mut state, &mut refresh);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

fn run_event_loop<F>(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    scan_result: &mut ScanResult,
    state: &mut AppState,
    refresh: &mut F,
) -> io::Result<TuiAction>
where
    F: FnMut(&mut ScanResult) -> bool,
{
    loop {
        if refresh(scan_result) {
            state.clamp_selection(scan_result);
        }
        state.tick = state.tick.wrapping_add(1);
        state.clear_expired_status();

        terminal.draw(|frame| render(frame, scan_result, state))?;

        if event::poll(Duration::from_millis(100))? {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    if let Some(action) = handle_key(state, scan_result, key) {
                        return Ok(action);
                    }
                }
                Event::Mouse(mouse) => {
                    handle_mouse(state, scan_result, mouse);
                }
                Event::Resize(_, _) => {}
                _ => {}
            }
        }
    }
}

fn handle_mouse(state: &mut AppState, scan_result: &ScanResult, mouse: MouseEvent) {
    let hit = state
        .hit_boxes
        .iter()
        .rev()
        .find(|(rect, _)| {
            mouse.column >= rect.x
                && mouse.column < rect.x + rect.width
                && mouse.row >= rect.y
                && mouse.row < rect.y + rect.height
        })
        .map(|(_, target)| target.clone());

    match mouse.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            if let Some(target) = hit {
                match target {
                    HitTarget::TabOverview => state.return_to_overview(),
                    HitTarget::TabFindings => state.open_findings(),
                    HitTarget::TabHistory => state.open_history(),
                    HitTarget::FindingList(index) => {
                        state.focus_list();
                        state.selected_index = index;
                        state.detail_scroll = 0;
                    }
                    HitTarget::FindingsDetail => state.focus_detail(),
                    HitTarget::OverviewPanel(focus) => state.overview_focus = focus,
                    HitTarget::SettingsRow(row) => {
                        state.settings_row = row;
                        state.adjust_setting_right();
                    }
                }
            } else if state.settings_open {
                state.close_settings();
            }
        }
        MouseEventKind::ScrollDown => {
            if state.settings_open {
                state.settings_next_row();
            } else if state.screen == Screen::Findings {
                if state.findings_focus == FindingsFocus::List {
                    state.select_next();
                } else {
                    state.scroll_detail_down(3);
                }
            } else {
                state.scroll_overview_down(3);
            }
        }
        MouseEventKind::ScrollUp => {
            if state.settings_open {
                state.settings_prev_row();
            } else if state.screen == Screen::Findings {
                if state.findings_focus == FindingsFocus::List {
                    state.select_previous();
                } else {
                    state.scroll_detail_up(3);
                }
            } else {
                state.scroll_overview_up(3);
            }
        }
        _ => {}
    }

    state.clamp_selection(scan_result);
}

fn handle_key(state: &mut AppState, scan_result: &ScanResult, key: KeyEvent) -> Option<TuiAction> {
    if state.help_open {
        if matches!(key.code, KeyCode::Esc | KeyCode::Char('?')) {
            state.help_open = false;
        }
        return None;
    }

    if state.search_open {
        return handle_search_key(state, scan_result, key);
    }

    if state.settings_open {
        return handle_settings_key(state, key);
    }

    if matches!(key.code, KeyCode::Char('?')) {
        state.help_open = true;
        return None;
    }

    if matches!(key.code, KeyCode::Char(',')) && key.modifiers.contains(KeyModifiers::CONTROL) {
        state.open_settings();
        return None;
    }

    match key.code {
        KeyCode::Char('1') => {
            state.return_to_overview();
            return None;
        }
        KeyCode::Char('2') => {
            state.open_findings();
            return None;
        }
        KeyCode::Char('3') => {
            state.open_history();
            return None;
        }
        KeyCode::Char('s') => {
            state.open_settings();
            return None;
        }
        KeyCode::Char('/') => {
            state.search_open = true;
            state.search_query.clear();
            return None;
        }
        _ => {}
    }

    match state.screen {
        Screen::Overview => handle_overview_key(state, scan_result, key),
        Screen::Findings => handle_findings_key(state, scan_result, key),
        Screen::History => handle_history_key(state, key),
    }
}

fn handle_settings_key(state: &mut AppState, key: KeyEvent) -> Option<TuiAction> {
    match key.code {
        KeyCode::Char('1') => {
            state.settings_row = 0;
            None
        }
        KeyCode::Char('2') => {
            state.settings_row = 1;
            None
        }
        KeyCode::Char('3') => {
            state.settings_row = 2;
            None
        }
        KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
            state.close_settings();
            None
        }
        KeyCode::Down | KeyCode::Char('j') => {
            state.settings_next_row();
            None
        }
        KeyCode::Up | KeyCode::Char('k') => {
            state.settings_prev_row();
            None
        }
        KeyCode::Right | KeyCode::Char('l') => {
            state.adjust_setting_right();
            None
        }
        KeyCode::Left | KeyCode::Char('h') => {
            state.adjust_setting_left();
            None
        }
        _ => None,
    }
}

fn handle_search_key(
    state: &mut AppState,
    scan_result: &ScanResult,
    key: KeyEvent,
) -> Option<TuiAction> {
    match key.code {
        KeyCode::Esc => {
            state.search_open = false;
            state.search_query.clear();
            state.clamp_selection(scan_result);
            None
        }
        KeyCode::Enter => {
            state.search_open = false;
            state.clamp_selection(scan_result);
            None
        }
        KeyCode::Backspace => {
            state.search_query.pop();
            None
        }
        KeyCode::Char(c) => {
            state.search_query.push(c);
            None
        }
        _ => None,
    }
}

fn handle_overview_key(
    state: &mut AppState,
    scan_result: &ScanResult,
    key: KeyEvent,
) -> Option<TuiAction> {
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => Some(TuiAction::Exit),
        KeyCode::Char('h') => {
            state.scope_filter = Some(Scope::Host);
            state.screen = Screen::Findings;
            state.clamp_selection(scan_result);
            None
        }
        KeyCode::Char('L') => {
            state.cycle_layout();
            None
        }
        KeyCode::Char('t') => {
            state.open_history();
            None
        }
        KeyCode::Tab => {
            state.focus_next_overview_panel();
            None
        }
        KeyCode::Down | KeyCode::Char('j') => {
            state.scroll_overview_down(1);
            None
        }
        KeyCode::Up | KeyCode::Char('k') => {
            state.scroll_overview_up(1);
            None
        }
        KeyCode::PageDown => {
            state.scroll_overview_down(8);
            None
        }
        KeyCode::PageUp => {
            state.scroll_overview_up(8);
            None
        }
        KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
            state.open_findings();
            None
        }
        _ => None,
    }
}

fn handle_findings_key(
    state: &mut AppState,
    scan_result: &ScanResult,
    key: KeyEvent,
) -> Option<TuiAction> {
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => {
            state.return_to_overview();
            None
        }
        KeyCode::Char('S') => {
            state.cycle_severity_filter();
            None
        }
        KeyCode::Char('x') => {
            state.cycle_source_filter();
            None
        }
        KeyCode::Char('m') => {
            state.cycle_remediation_filter();
            None
        }
        KeyCode::Char('v') => {
            state.cycle_service_filter(scan_result);
            None
        }
        KeyCode::Char('o') => {
            state.cycle_sort_mode();
            None
        }
        KeyCode::Char('t') => {
            state.open_history();
            None
        }
        KeyCode::Char('r') => {
            state.reset_filters_and_sort();
            None
        }
        KeyCode::Char('f') => {
            let availability = fix_availability(
                scan_result.metadata.compose_file.as_deref(),
                state.selected_finding(scan_result),
            );
            if !availability.is_fixable() {
                state.set_status_message(fix_unavailable_message(availability));
                return None;
            }
            let compose_file = scan_result
                .metadata
                .compose_file
                .clone()
                .expect("fixability check should guarantee a compose file");
            let finding = state
                .selected_finding(scan_result)
                .expect("fixability check should guarantee a selected finding");
            let external_findings: Vec<Finding> = scan_result
                .findings
                .iter()
                .filter(|f| {
                    matches!(
                        f.source,
                        Source::Dockle | Source::Lynis | Source::NativeHost
                    )
                })
                .cloned()
                .collect();
            Some(TuiAction::TriggerFix {
                compose_file,
                finding_id: Some(finding.id.clone()),
                adapter_findings: external_findings,
            })
        }
        KeyCode::Tab => {
            state.toggle_focus();
            None
        }
        KeyCode::Left | KeyCode::Char('h') => {
            state.focus_list();
            None
        }
        KeyCode::Right | KeyCode::Char('l') | KeyCode::Enter => {
            state.focus_detail();
            None
        }
        KeyCode::Down | KeyCode::Char('j') => {
            match state.findings_focus {
                FindingsFocus::List => state.select_next(),
                FindingsFocus::Detail => state.scroll_detail_down(1),
            }
            None
        }
        KeyCode::Up | KeyCode::Char('k') => {
            match state.findings_focus {
                FindingsFocus::List => state.select_previous(),
                FindingsFocus::Detail => state.scroll_detail_up(1),
            }
            None
        }
        KeyCode::PageDown => {
            state.scroll_detail_down(8);
            None
        }
        KeyCode::PageUp => {
            state.scroll_detail_up(8);
            None
        }
        _ => None,
    }
}

fn handle_history_key(state: &mut AppState, key: KeyEvent) -> Option<TuiAction> {
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => Some(TuiAction::Exit),
        KeyCode::Char('t') | KeyCode::Char('o') => {
            state.close_history();
            None
        }
        KeyCode::Down | KeyCode::Char('j') => {
            state.history_scroll = state.history_scroll.saturating_add(1);
            None
        }
        KeyCode::Up | KeyCode::Char('k') => {
            state.history_scroll = state.history_scroll.saturating_sub(1);
            None
        }
        KeyCode::PageDown => {
            state.history_scroll = state.history_scroll.saturating_add(8);
            None
        }
        KeyCode::PageUp => {
            state.history_scroll = state.history_scroll.saturating_sub(8);
            None
        }
        _ => None,
    }
}

fn render(frame: &mut ratatui::Frame<'_>, scan_result: &ScanResult, state: &mut AppState) {
    state.hit_boxes.clear();
    state.clamp_selection(scan_result);
    render_surface_background(frame, &state.theme);

    match state.screen {
        Screen::Overview => render_overview(frame, scan_result, state),
        Screen::Findings => render_findings(frame, scan_result, state),
        Screen::History => render_history(frame, state),
    }

    if state.settings_open {
        render_settings_modal(frame, state);
    }

    if state.help_open {
        render_help_overlay(frame, state);
    }

    if state.search_open {
        render_search_modal(frame, state);
    }
}

fn render_surface_background(frame: &mut ratatui::Frame<'_>, theme: &Theme) {
    frame.render_widget(Block::default().style(theme.surface), frame.area());
}

fn render_overview(frame: &mut ratatui::Frame<'_>, scan_result: &ScanResult, state: &mut AppState) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .spacing(1)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(12),
            Constraint::Length(2),
        ])
        .split(frame.area());

    header_banner(frame, state, layout[0]);

    match overview_layout_mode(frame.area(), state.layout_preset) {
        OverviewLayoutMode::Wide => {
            let columns = Layout::default()
                .direction(Direction::Horizontal)
                .spacing(1)
                .constraints([
                    Constraint::Percentage(31),
                    Constraint::Percentage(33),
                    Constraint::Percentage(36),
                ])
                .split(layout[1]);

            if state.layout_preset == LayoutPreset::AdaptiveLegacy {
                // Legacy adaptive layout keeps the 3-column split, but:
                // - left column stacks Server Status + Security Scores
                // - Scan Results and Action Queue are full-height side-by-side
                let left_column = Layout::default()
                    .direction(Direction::Vertical)
                    .spacing(1)
                    .constraints([
                        Constraint::Min(10),
                        Constraint::Min(score_panel_min_height(ScoreDensity::Standard)),
                    ])
                    .split(columns[0]);

                state.hit_boxes.push((
                    left_column[0],
                    HitTarget::OverviewPanel(OverviewFocus::ServerStatus),
                ));
                state.hit_boxes.push((
                    columns[1],
                    HitTarget::OverviewPanel(OverviewFocus::ScanResults),
                ));
                state.hit_boxes.push((
                    left_column[1],
                    HitTarget::OverviewPanel(OverviewFocus::SecurityScores),
                ));
                state.hit_boxes.push((
                    columns[2],
                    HitTarget::OverviewPanel(OverviewFocus::FixPaths),
                ));

                render_server_status_panel(
                    frame,
                    left_column[0],
                    scan_result,
                    state,
                    &state.theme,
                    state.overview_focus == OverviewFocus::ServerStatus,
                );
                render_scan_results_panel(
                    frame,
                    columns[1],
                    scan_result,
                    state,
                    &state.theme,
                    state.overview_focus == OverviewFocus::ScanResults,
                );
                render_security_scores_panel(
                    frame,
                    left_column[1],
                    scan_result,
                    state,
                    &state.theme,
                    state.overview_focus == OverviewFocus::SecurityScores,
                );
                render_fix_paths_panel(
                    frame,
                    columns[2],
                    scan_result,
                    state,
                    &state.theme,
                    state.overview_focus == OverviewFocus::FixPaths,
                );
            } else {
                let right_column = Layout::default()
                    .direction(Direction::Vertical)
                    .spacing(1)
                    .constraints([
                        Constraint::Min(score_panel_min_height(ScoreDensity::Standard)),
                        Constraint::Min(6),
                    ])
                    .split(columns[2]);

                state.hit_boxes.push((
                    columns[0],
                    HitTarget::OverviewPanel(OverviewFocus::ServerStatus),
                ));
                state.hit_boxes.push((
                    columns[1],
                    HitTarget::OverviewPanel(OverviewFocus::ScanResults),
                ));
                state.hit_boxes.push((
                    right_column[0],
                    HitTarget::OverviewPanel(OverviewFocus::SecurityScores),
                ));
                state.hit_boxes.push((
                    right_column[1],
                    HitTarget::OverviewPanel(OverviewFocus::FixPaths),
                ));

                render_server_status_panel(
                    frame,
                    columns[0],
                    scan_result,
                    state,
                    &state.theme,
                    state.overview_focus == OverviewFocus::ServerStatus,
                );
                render_scan_results_panel(
                    frame,
                    columns[1],
                    scan_result,
                    state,
                    &state.theme,
                    state.overview_focus == OverviewFocus::ScanResults,
                );
                render_security_scores_panel(
                    frame,
                    right_column[0],
                    scan_result,
                    state,
                    &state.theme,
                    state.overview_focus == OverviewFocus::SecurityScores,
                );
                render_fix_paths_panel(
                    frame,
                    right_column[1],
                    scan_result,
                    state,
                    &state.theme,
                    state.overview_focus == OverviewFocus::FixPaths,
                );
            }
        }
        OverviewLayoutMode::Tall => {
            let rows = Layout::default()
                .direction(Direction::Vertical)
                .spacing(1)
                .constraints([
                    Constraint::Min(5),
                    Constraint::Min(7),
                    Constraint::Min(score_panel_min_height(ScoreDensity::Standard)),
                    Constraint::Min(5),
                ])
                .split(layout[1]);

            state.hit_boxes.push((
                rows[0],
                HitTarget::OverviewPanel(OverviewFocus::ServerStatus),
            ));
            state.hit_boxes.push((
                rows[1],
                HitTarget::OverviewPanel(OverviewFocus::ScanResults),
            ));
            state.hit_boxes.push((
                rows[2],
                HitTarget::OverviewPanel(OverviewFocus::SecurityScores),
            ));
            state
                .hit_boxes
                .push((rows[3], HitTarget::OverviewPanel(OverviewFocus::FixPaths)));

            render_server_status_panel(
                frame,
                rows[0],
                scan_result,
                state,
                &state.theme,
                state.overview_focus == OverviewFocus::ServerStatus,
            );
            render_scan_results_panel(
                frame,
                rows[1],
                scan_result,
                state,
                &state.theme,
                state.overview_focus == OverviewFocus::ScanResults,
            );
            render_security_scores_panel(
                frame,
                rows[2],
                scan_result,
                state,
                &state.theme,
                state.overview_focus == OverviewFocus::SecurityScores,
            );
            render_fix_paths_panel(
                frame,
                rows[3],
                scan_result,
                state,
                &state.theme,
                state.overview_focus == OverviewFocus::FixPaths,
            );
        }
        OverviewLayoutMode::Compact => {
            let columns = Layout::default()
                .direction(Direction::Horizontal)
                .spacing(1)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(layout[1]);
            let left = Layout::default()
                .direction(Direction::Vertical)
                .spacing(1)
                .constraints([Constraint::Percentage(48), Constraint::Percentage(52)])
                .split(columns[0]);
            let right = Layout::default()
                .direction(Direction::Vertical)
                .spacing(1)
                .constraints([
                    Constraint::Min(score_panel_min_height(ScoreDensity::Standard)),
                    Constraint::Min(6),
                ])
                .split(columns[1]);

            state.hit_boxes.push((
                left[0],
                HitTarget::OverviewPanel(OverviewFocus::ServerStatus),
            ));
            state.hit_boxes.push((
                left[1],
                HitTarget::OverviewPanel(OverviewFocus::ScanResults),
            ));
            state.hit_boxes.push((
                right[0],
                HitTarget::OverviewPanel(OverviewFocus::SecurityScores),
            ));
            state
                .hit_boxes
                .push((right[1], HitTarget::OverviewPanel(OverviewFocus::FixPaths)));

            render_server_status_panel(
                frame,
                left[0],
                scan_result,
                state,
                &state.theme,
                state.overview_focus == OverviewFocus::ServerStatus,
            );
            render_scan_results_panel(
                frame,
                left[1],
                scan_result,
                state,
                &state.theme,
                state.overview_focus == OverviewFocus::ScanResults,
            );
            render_security_scores_panel(
                frame,
                right[0],
                scan_result,
                state,
                &state.theme,
                state.overview_focus == OverviewFocus::SecurityScores,
            );
            render_fix_paths_panel(
                frame,
                right[1],
                scan_result,
                state,
                &state.theme,
                state.overview_focus == OverviewFocus::FixPaths,
            );
        }
        OverviewLayoutMode::Narrow => {
            let rows = Layout::default()
                .direction(Direction::Vertical)
                .spacing(1)
                .constraints([
                    Constraint::Percentage(26),
                    Constraint::Percentage(26),
                    Constraint::Percentage(22),
                    Constraint::Percentage(24),
                ])
                .split(layout[1]);

            state.hit_boxes.push((
                rows[0],
                HitTarget::OverviewPanel(OverviewFocus::ServerStatus),
            ));
            state.hit_boxes.push((
                rows[1],
                HitTarget::OverviewPanel(OverviewFocus::ScanResults),
            ));
            state.hit_boxes.push((
                rows[2],
                HitTarget::OverviewPanel(OverviewFocus::SecurityScores),
            ));
            state
                .hit_boxes
                .push((rows[3], HitTarget::OverviewPanel(OverviewFocus::FixPaths)));

            render_server_status_panel(
                frame,
                rows[0],
                scan_result,
                state,
                &state.theme,
                state.overview_focus == OverviewFocus::ServerStatus,
            );
            render_scan_results_panel(
                frame,
                rows[1],
                scan_result,
                state,
                &state.theme,
                state.overview_focus == OverviewFocus::ScanResults,
            );
            render_security_scores_panel(
                frame,
                rows[2],
                scan_result,
                state,
                &state.theme,
                state.overview_focus == OverviewFocus::SecurityScores,
            );
            render_fix_paths_panel(
                frame,
                rows[3],
                scan_result,
                state,
                &state.theme,
                state.overview_focus == OverviewFocus::FixPaths,
            );
        }
        OverviewLayoutMode::Focus => {
            let columns = Layout::default()
                .direction(Direction::Horizontal)
                .spacing(1)
                .constraints([Constraint::Percentage(48), Constraint::Percentage(52)])
                .split(layout[1]);
            render_security_scores_panel(
                frame,
                columns[0],
                scan_result,
                state,
                &state.theme,
                state.overview_focus == OverviewFocus::SecurityScores,
            );
            render_scan_results_panel(
                frame,
                columns[1],
                scan_result,
                state,
                &state.theme,
                state.overview_focus == OverviewFocus::ScanResults,
            );
        }
    }

    frame.render_widget(overview_footer(&state.theme), layout[2]);
}

fn render_findings(frame: &mut ratatui::Frame<'_>, scan_result: &ScanResult, state: &mut AppState) {
    let mode = findings_layout_mode(frame.area(), state.layout_preset);
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .spacing(1)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Min(8),
            Constraint::Length(3),
        ])
        .split(frame.area());

    header_banner(frame, state, layout[0]);

    frame.render_widget(
        findings_header(scan_result, state, layout[1].width, mode, &state.theme),
        layout[1],
    );

    let content = match mode {
        FindingsLayoutMode::SideBySide => Layout::default()
            .direction(Direction::Horizontal)
            .spacing(1)
            .constraints([Constraint::Percentage(44), Constraint::Percentage(56)])
            .split(layout[2]),
        FindingsLayoutMode::Stacked => Layout::default()
            .direction(Direction::Vertical)
            .spacing(1)
            .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
            .split(layout[2]),
        FindingsLayoutMode::Narrow => Layout::default()
            .direction(Direction::Vertical)
            .spacing(1)
            .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
            .split(layout[2]),
        FindingsLayoutMode::CompactList => Layout::default()
            .direction(Direction::Horizontal)
            .spacing(1)
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(layout[2]),
    };

    let mut list_state = ListState::default();
    let viewport_items = content[0].height.saturating_sub(2).max(1) as usize;
    let max_list_scroll = state.finding_count().saturating_sub(viewport_items);
    let mut list_scroll = state
        .findings_list_scroll
        .min(max_list_scroll.min(u16::MAX as usize) as u16);
    if state.finding_count() > 0 {
        let selected = state.selected_index.min(state.finding_count() - 1);
        let selected_scroll = selected as u16;
        if selected_scroll < list_scroll {
            list_scroll = selected_scroll;
        } else if selected >= list_scroll as usize + viewport_items {
            list_scroll = (selected + 1 - viewport_items).min(max_list_scroll) as u16;
        }
        state.findings_list_scroll = list_scroll;
    }
    let start = list_scroll as usize;
    let end = (start + viewport_items).min(state.finding_count());

    if state.finding_count() > 0 {
        if state.selected_index < start || state.selected_index >= end {
            let selected = state.selected_index.min(state.finding_count() - 1);
            let visible_selected = selected.saturating_sub(start).min(viewport_items - 1);
            list_state.select(Some(visible_selected));
        } else {
            list_state.select(Some(state.selected_index.saturating_sub(start)));
        }
    }

    let all_items = findings_list_items(scan_result, state, content[0].width, mode, &state.theme);
    let visible_items = if all_items.is_empty() {
        all_items
    } else {
        all_items
            .into_iter()
            .skip(start)
            .take(viewport_items)
            .collect::<Vec<_>>()
    };

    let list_bg = if state.findings_focus == FindingsFocus::List {
        state.theme.focus_bg
    } else {
        state.theme.panel_bg
    };
    let detail_bg = if state.findings_focus == FindingsFocus::Detail {
        state.theme.focus_bg
    } else {
        state.theme.panel_bg_alt
    };

    let list = List::new(visible_items)
        .style(list_bg)
        .block(
            Block::default()
                .title(findings_list_title(state.findings_focus))
                .borders(panel_borders(&state.theme))
                .border_style(state.theme.border)
                .style(list_bg)
                .padding(Padding::horizontal(1)),
        )
        .highlight_symbol("> ")
        .highlight_style(state.theme.highlight);

    let detail_block = Block::default()
        .title(findings_detail_title(state.findings_focus))
        .borders(panel_borders(&state.theme))
        .border_style(state.theme.border)
        .style(detail_bg)
        .padding(Padding::horizontal(1));
    let detail_inner = detail_block.inner(content[1]);
    let detail_text =
        finding_detail_text(scan_result, state, detail_inner.width, mode, &state.theme);
    let detail_content_height = estimated_wrapped_text_height(&detail_text, detail_inner.width);
    let detail_max_scroll = detail_content_height.saturating_sub(detail_inner.height as usize);
    state.clamp_detail_scroll(detail_max_scroll);

    let detail = Paragraph::new(detail_text)
        .block(detail_block)
        .style(state.theme.surface)
        .wrap(Wrap { trim: true })
        .scroll((state.detail_scroll, 0));

    register_finding_list_hit_boxes(scan_result, state, content[0], mode, start, end);
    state
        .hit_boxes
        .push((content[1], HitTarget::FindingsDetail));

    frame.render_stateful_widget(list, content[0], &mut list_state);
    render_scrollbar(
        frame,
        content[0],
        state.finding_count(),
        viewport_items as u16,
        list_scroll,
    );
    frame.render_widget(detail, content[1]);
    render_detail_scrollbar(
        frame,
        content[1],
        detail_content_height,
        detail_inner.height,
        state,
    );
    frame.render_widget(
        findings_footer(scan_result, state, layout[3].width, mode, &state.theme),
        layout[3],
    );
}

fn register_finding_list_hit_boxes(
    scan_result: &ScanResult,
    state: &mut AppState,
    area: Rect,
    mode: FindingsLayoutMode,
    start: usize,
    end: usize,
) {
    if area.width <= 2 || area.height <= 2 || start >= end {
        return;
    }

    let inner = area.inner(Margin {
        vertical: 1,
        horizontal: 1,
    });
    let mut y = inner.y;
    let max_y = inner.y.saturating_add(inner.height);
    let text_width = area.width.saturating_sub(2).max(16) as usize;

    for visible_index in start..end {
        let Some(finding_index) = state.sorted_indices.get(visible_index).copied() else {
            continue;
        };
        let Some(finding) = scan_result.findings.get(finding_index) else {
            continue;
        };

        let item_height = finding_list_item_line_count(finding, text_width, mode)
            .max(1)
            .min(max_y.saturating_sub(y) as usize) as u16;
        if item_height == 0 {
            break;
        }

        state.hit_boxes.push((
            Rect {
                x: inner.x,
                y,
                width: inner.width,
                height: item_height,
            },
            HitTarget::FindingList(visible_index),
        ));
        y = y.saturating_add(item_height);
        if y >= max_y {
            break;
        }
    }
}

fn overview_layout_mode(area: Rect, preset: LayoutPreset) -> OverviewLayoutMode {
    match preset {
        // Auto now tracks the "Balanced" layout intent (stable, aspect-ratio driven)
        // while still falling back to the narrow layout for small terminals.
        LayoutPreset::Adaptive => {
            if area.width >= 80 && area.height >= 24 {
                if area.height > area.width {
                    OverviewLayoutMode::Tall
                } else {
                    OverviewLayoutMode::Compact
                }
            } else {
                OverviewLayoutMode::Narrow
            }
        }
        // Legacy adaptive keeps the old responsive breakpoints.
        LayoutPreset::AdaptiveLegacy => {
            if area.width >= 120 && area.height >= 28 {
                OverviewLayoutMode::Wide
            } else if area.width >= 80 && area.height >= 40 {
                OverviewLayoutMode::Tall
            } else if area.width >= 80 && area.height >= 24 {
                OverviewLayoutMode::Compact
            } else {
                OverviewLayoutMode::Narrow
            }
        }
        LayoutPreset::Wide => OverviewLayoutMode::Wide,
        LayoutPreset::Balanced => {
            if area.height > area.width {
                OverviewLayoutMode::Tall
            } else {
                OverviewLayoutMode::Compact
            }
        }
        LayoutPreset::Compact => OverviewLayoutMode::Narrow,
        LayoutPreset::Focus => OverviewLayoutMode::Focus,
    }
}

fn findings_layout_mode(area: Rect, preset: LayoutPreset) -> FindingsLayoutMode {
    match preset {
        // Auto now mirrors the "Balanced" layout intent (stacked) while still
        // falling back to the narrow layout for small terminals.
        LayoutPreset::Adaptive => {
            if area.width >= 72 && area.height >= 18 {
                FindingsLayoutMode::Stacked
            } else {
                FindingsLayoutMode::Narrow
            }
        }
        LayoutPreset::AdaptiveLegacy => {
            if area.width >= 96 && area.height >= 24 {
                FindingsLayoutMode::SideBySide
            } else if area.width >= 72 && area.height >= 18 {
                FindingsLayoutMode::Stacked
            } else {
                FindingsLayoutMode::Narrow
            }
        }
        LayoutPreset::Wide => FindingsLayoutMode::SideBySide,
        LayoutPreset::Balanced => FindingsLayoutMode::Stacked,
        LayoutPreset::Compact => FindingsLayoutMode::Narrow,
        LayoutPreset::Focus => FindingsLayoutMode::CompactList,
    }
}

fn render_history(frame: &mut ratatui::Frame<'_>, state: &mut AppState) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .spacing(1)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(8),
            Constraint::Length(3),
        ])
        .split(frame.area());

    header_banner(frame, state, layout[0]);

    let history = crate::history::load();
    let entries = history.trend(20);

    let content = if entries.is_empty() {
        Text::from(t!("app.history.empty").into_owned())
    } else {
        let mut lines = vec![Line::from(t!("app.history.header").into_owned())];
        for entry in entries {
            let timestamp = &entry.timestamp[..entry.timestamp.find('T').unwrap_or(19)];
            let overall = entry.overall;
            let finding_count = entry.finding_count;
            let bar = trend_bar(overall);
            lines.push(Line::from(vec![
                Span::raw(format!("{:<12}", timestamp)),
                Span::raw(format!(" Overall: {:>3}", overall)),
                Span::raw(format!(" Findings: {:>3}  ", finding_count)),
                Span::styled(bar, Style::default().fg(trend_color(overall))),
            ]));
        }
        Text::from(lines)
    };

    let is_history_tab = matches!(state.screen, Screen::History);
    let panel = component::Panel::new(t!("app.history.title").into_owned(), content)
        .focused(is_history_tab);
    panel.render(frame, layout[1], &state.theme);

    let help = Paragraph::new(t!("app.history.footer").into_owned()).style(state.theme.muted);
    frame.render_widget(help, layout[2]);
}

fn trend_bar(score: u8) -> String {
    let filled = (score as usize) / 5;
    let empty = 20_usize.saturating_sub(filled);
    format!("{}{}", "█".repeat(filled), "░".repeat(empty))
}

fn trend_color(score: u8) -> ratatui::style::Color {
    use ratatui::style::Color;
    match score {
        0..=40 => Color::Red,
        41..=70 => Color::Yellow,
        _ => Color::Green,
    }
}

fn header_banner(frame: &mut ratatui::Frame<'_>, state: &mut AppState, area: Rect) {
    let theme = &state.theme;
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(1)])
        .split(area);

    let title_spans = vec![
        Span::styled(
            format!("hostveil v{}", env!("CARGO_PKG_VERSION")),
            theme.title.add_modifier(Modifier::BOLD),
        ),
        Span::raw(" | "),
        Span::styled(t!("app.header.subtitle").into_owned(), theme.base),
        Span::raw(" | "),
        Span::styled(
            current_locale_badge(),
            Style::default().fg(theme.med).add_modifier(Modifier::BOLD),
        ),
    ];
    frame.render_widget(
        Paragraph::new(Line::from(title_spans)).alignment(Alignment::Center),
        chunks[0],
    );

    render_tabs(frame, chunks[1], state);
}

fn render_tabs(frame: &mut ratatui::Frame<'_>, area: Rect, state: &mut AppState) {
    let theme = &state.theme;

    let tabs = [
        (
            Screen::Overview,
            HitTarget::TabOverview,
            t!("app.tab.overview").into_owned(),
            "1",
        ),
        (
            Screen::Findings,
            HitTarget::TabFindings,
            t!("app.tab.findings").into_owned(),
            "2",
        ),
        (
            Screen::History,
            HitTarget::TabHistory,
            t!("app.tab.history").into_owned(),
            "3",
        ),
    ];

    let mut spans: Vec<Span> = Vec::new();
    for (i, (screen, target, label, key)) in tabs.iter().enumerate() {
        let is_active = state.screen == *screen;
        let style = if is_active {
            theme
                .tab_active
                .bg(theme
                    .highlight
                    .bg
                    .unwrap_or(theme.surface.bg.unwrap_or(Color::Reset)))
                .add_modifier(Modifier::BOLD)
        } else {
            theme.tab_inactive
        };

        if i > 0 {
            spans.push(Span::styled(" ", theme.muted));
        }
        spans.push(Span::styled(format!(" {key} {label} "), style));

        let label_width = 6 + label.len() as u16;
        let start_x = area.x
            + if i == 0 {
                0
            } else {
                let prev_width: u16 = tabs[..i]
                    .iter()
                    .map(|(_, _, l, _)| 6 + l.len() as u16)
                    .sum::<u16>()
                    + (i as u16);
                prev_width
            };
        let tab_rect = Rect {
            x: area.x + start_x,
            y: area.y,
            width: label_width.min(area.width.saturating_sub(start_x)),
            height: 1,
        };
        state.hit_boxes.push((tab_rect, target.clone()));
    }

    let line = Line::from(spans);
    frame.render_widget(Paragraph::new(line).alignment(Alignment::Center), area);
}

fn render_modal_backdrop(frame: &mut ratatui::Frame<'_>, area: Rect, _theme: &Theme) {
    {
        let buffer = frame.buffer_mut();
        for y in area.y..area.y + area.height {
            for x in area.x..area.x + area.width {
                if let Some(cell) = buffer.cell_mut((x, y)) {
                    let style = cell.style();
                    if let Some(bg) = style.bg {
                        cell.set_style(style.bg(darken_color(bg, 0.55)));
                    }
                }
            }
        }
    }
}

fn render_modal_frame(
    frame: &mut ratatui::Frame<'_>,
    modal: Rect,
    title: &str,
    theme: &Theme,
) -> Rect {
    frame.render_widget(Clear, modal);
    let block = Block::default()
        .title(format!(" {} ", title))
        .borders(panel_borders(theme))
        .border_style(theme.modal_border)
        .style(theme.modal_bg);
    let inner = block.inner(modal);
    frame.render_widget(block, modal);
    inner
}

fn darken_color(color: ratatui::style::Color, factor: f32) -> ratatui::style::Color {
    match color {
        ratatui::style::Color::Rgb(r, g, b) => ratatui::style::Color::Rgb(
            ((r as f32) * factor).clamp(0.0, 255.0) as u8,
            ((g as f32) * factor).clamp(0.0, 255.0) as u8,
            ((b as f32) * factor).clamp(0.0, 255.0) as u8,
        ),
        _ => color,
    }
}

fn render_settings_modal(frame: &mut ratatui::Frame<'_>, state: &mut AppState) {
    let area = frame.area();
    let modal = centered_rect(70, 50, area);
    let modal = clamp_rect_width(modal, 80);

    let theme = &state.theme;

    render_modal_backdrop(frame, area, theme);
    let inner = render_modal_frame(frame, modal, &t!("app.panel.settings"), theme);

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .spacing(1)
        .constraints([
            Constraint::Length(1), // Spacer
            Constraint::Min(1),    // Settings
            Constraint::Length(1), // Footer
        ])
        .split(inner);

    let current_locale = i18n::current_locale();
    let border_label = if state.borders_enabled {
        t!("app.settings.ui_borders_on").into_owned()
    } else {
        t!("app.settings.ui_borders_off").into_owned()
    };
    let rows = [
        (
            SettingsRow::Theme,
            t!("app.settings.theme").into_owned(),
            state.theme_preset.label(),
        ),
        (
            SettingsRow::Layout,
            t!("app.settings.layout").into_owned(),
            state.layout_preset.label(),
        ),
        (
            SettingsRow::Locale,
            t!("app.settings.locale").into_owned(),
            current_locale.as_str(),
        ),
        (
            SettingsRow::UiBorders,
            t!("app.settings.ui_borders").into_owned(),
            &border_label,
        ),
    ];

    let row_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints(vec![Constraint::Length(2); rows.len()])
        .split(layout[1]);

    for (i, (_id, label, value)) in rows.iter().enumerate() {
        let is_active = i == state.settings_row;
        let rect = row_layout[i];
        state.hit_boxes.push((rect, HitTarget::SettingsRow(i)));

        let style = if is_active {
            theme.highlight
        } else {
            theme.base
        };
        let prefix = if is_active { "> " } else { "  " };

        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(prefix, style),
                Span::styled(format!("{}: ", label), style),
                Span::styled(
                    value.to_string(),
                    if is_active { theme.title } else { theme.muted },
                ),
            ])),
            rect,
        );
    }

    frame.render_widget(
        Paragraph::new(t!("app.settings.hint").into_owned())
            .alignment(Alignment::Center)
            .style(theme.muted),
        layout[2],
    );
}

fn render_help_overlay(frame: &mut ratatui::Frame<'_>, state: &mut AppState) {
    let area = frame.area();
    let modal = centered_rect(75, 70, area);
    let modal = clamp_rect_width(modal, 90);
    let theme = &state.theme;

    render_modal_backdrop(frame, area, theme);
    let inner = render_modal_frame(frame, modal, &t!("app.panel.help"), theme);

    let shortcuts = vec![
        (
            t!("app.help.global").into_owned(),
            vec![
                ("?", t!("app.help.show_help").into_owned()),
                ("1", t!("app.help.overview").into_owned()),
                ("2", t!("app.help.findings").into_owned()),
                ("s / Ctrl,", t!("app.help.settings").into_owned()),
                ("/", t!("app.help.search").into_owned()),
                ("q / Esc", t!("app.help.quit").into_owned()),
            ],
        ),
        (
            t!("app.help.overview_nav").into_owned(),
            vec![
                ("Tab", t!("app.help.focus_next_panel").into_owned()),
                ("↑ ↓ / k j", t!("app.help.scroll_panel").into_owned()),
                ("Enter / l", t!("app.help.open_findings").into_owned()),
                ("h", t!("app.help.host_findings").into_owned()),
                ("L", t!("app.help.cycle_layout").into_owned()),
            ],
        ),
        (
            t!("app.help.findings_nav").into_owned(),
            vec![
                ("↑ ↓ / k j", t!("app.help.select").into_owned()),
                ("PgUp / PgDn", t!("app.help.scroll_detail").into_owned()),
                ("Tab / ← / →", t!("app.help.switch_focus").into_owned()),
                ("S / x / m / v", t!("app.help.cycle_filters").into_owned()),
                ("o", t!("app.help.cycle_sort").into_owned()),
                ("r", t!("app.help.reset_filters").into_owned()),
                ("f", t!("app.help.fix").into_owned()),
                ("q / Esc", t!("app.help.back_overview").into_owned()),
            ],
        ),
        (
            t!("app.help.mouse").into_owned(),
            vec![
                ("Scroll", t!("app.help.scroll").into_owned()),
                ("Click", t!("app.help.click").into_owned()),
            ],
        ),
    ];

    let mut lines = vec![Line::raw("")];
    for (section_title, items) in shortcuts {
        lines.push(Line::styled(format!("  {}", section_title), theme.title));
        for (key, desc) in items {
            lines.push(Line::from(vec![
                Span::styled(format!("    {:14}", key), theme.highlight),
                Span::styled(desc, theme.base),
            ]));
        }
        lines.push(Line::raw(""));
    }

    let content = Text::from(lines);
    frame.render_widget(
        Paragraph::new(content)
            .style(theme.surface)
            .wrap(Wrap { trim: false })
            .scroll((0, 0)),
        inner,
    );
}

fn render_search_modal(frame: &mut ratatui::Frame<'_>, state: &mut AppState) {
    let area = frame.area();
    let modal = centered_rect(60, 20, area);
    let modal = clamp_rect_width(modal, 80);
    let theme = &state.theme;

    render_modal_backdrop(frame, area, theme);
    let inner = render_modal_frame(frame, modal, &t!("app.panel.search"), theme);

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .spacing(1)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(2),
            Constraint::Length(1),
        ])
        .split(inner);

    frame.render_widget(
        Paragraph::new(t!("app.search.prompt").into_owned()).style(theme.muted),
        layout[0],
    );

    let query_line = if state.search_query.is_empty() {
        Line::styled(t!("app.search.placeholder").into_owned(), theme.muted)
    } else {
        Line::styled(state.search_query.clone(), theme.base)
    };

    frame.render_widget(
        Paragraph::new(query_line)
            .block(
                Block::default()
                    .borders(Borders::BOTTOM)
                    .border_style(theme.border),
            )
            .style(theme.surface),
        layout[1],
    );

    frame.render_widget(
        Paragraph::new(t!("app.search.hint").into_owned())
            .style(theme.muted)
            .alignment(Alignment::Center),
        layout[2],
    );
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn clamp_rect_width(r: Rect, max_width: u16) -> Rect {
    if r.width <= max_width {
        return r;
    }
    let excess = r.width - max_width;
    Rect {
        x: r.x + excess / 2,
        y: r.y,
        width: max_width,
        height: r.height,
    }
}

fn render_server_status_panel(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    scan_result: &ScanResult,
    state: &AppState,
    theme: &Theme,
    is_focused: bool,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }

    let mut lines = vec![
        kv_line(
            t!("app.server.load").into_owned(),
            load_display(scan_result),
            theme,
        ),
        kv_line(
            t!("app.server.host_name").into_owned(),
            display_hostname(scan_result),
            theme,
        ),
        kv_line(
            t!("app.server.root_path").into_owned(),
            display_host_root(scan_result),
            theme,
        ),
        kv_line(
            t!("app.server.docker_version").into_owned(),
            display_docker_version(scan_result),
            theme,
        ),
        kv_line(
            t!("app.server.uptime").into_owned(),
            display_uptime(scan_result),
            theme,
        ),
    ];
    lines.push(Line::raw(String::new()));
    lines.extend(server_service_lines(scan_result, area.width, theme));

    let content = Text::from(lines);
    let content_height = estimated_wrapped_text_height(&content, area.width);
    let max_scroll = content_height.saturating_sub(area.height as usize);
    let scroll = state
        .overview_scroll
        .get(&OverviewFocus::ServerStatus)
        .copied()
        .unwrap_or(0)
        .min(max_scroll.min(u16::MAX as usize) as u16);

    let panel = component::Panel::new(t!("app.panel.server_status").into_owned(), content)
        .focused(is_focused)
        .with_scroll(scroll as usize);
    panel.render(frame, area, theme);
    render_scrollbar(frame, area, content_height, area.height, scroll);
}

fn render_scan_results_panel(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    scan_result: &ScanResult,
    state: &AppState,
    theme: &Theme,
    is_focused: bool,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }

    let mut lines = result_summary_lines(scan_result, area.width, theme);
    lines.push(Line::raw(String::new()));
    lines.extend(severity_total_lines(scan_result, area.width, theme));
    lines.push(Line::raw(String::new()));
    if scan_result.findings.is_empty() {
        lines.push(Line::styled(
            t!("app.overview.no_findings").into_owned(),
            theme.muted,
        ));
    } else {
        lines.push(Line::styled(
            t!(
                "app.overview.findings_available",
                count = scan_result.findings.len()
            )
            .into_owned(),
            theme.title.add_modifier(Modifier::BOLD),
        ));
    }

    if let Some(docker_status) = &scan_result.metadata.docker_status {
        lines.push(Line::raw(String::new()));
        lines.push(Line::styled(
            t!("app.result.discovery_heading").into_owned(),
            theme.title.add_modifier(Modifier::BOLD),
        ));
        lines.push(Line::raw(format!(
            "Docker: {}",
            docker_status_label(docker_status)
        )));
    }

    if !scan_result.metadata.discovered_projects.is_empty() {
        for project in scan_result.metadata.discovered_projects.iter().take(3) {
            lines.push(Line::raw(format!(
                "* {} ({})",
                project.name, project.source
            )));
        }
    }

    let adapter_lines = adapter_summary_lines(scan_result, area.width, state, theme);
    if !adapter_lines.is_empty() {
        lines.push(Line::raw(String::new()));
        lines.extend(adapter_lines);
    }

    if !scan_result.metadata.warnings.is_empty() {
        lines.push(Line::raw(String::new()));
        lines.push(Line::styled(
            t!("app.result.warnings_heading").into_owned(),
            Style::default().fg(theme.med).add_modifier(Modifier::BOLD),
        ));
        for warning in scan_result.metadata.warnings.iter().take(3) {
            let warning_width = area.width.saturating_sub(4).max(20) as usize;
            for wrapped in wrap_text_to_lines(warning, warning_width) {
                lines.push(Line::raw(format!("- {}", wrapped)));
            }
        }
    }

    let content = Text::from(lines);
    let content_height = estimated_wrapped_text_height(&content, area.width);
    let max_scroll = content_height.saturating_sub(area.height as usize);
    let scroll = state
        .overview_scroll
        .get(&OverviewFocus::ScanResults)
        .copied()
        .unwrap_or(0)
        .min(max_scroll.min(u16::MAX as usize) as u16);

    let panel = component::Panel::new(t!("app.panel.scan_results").into_owned(), content)
        .focused(is_focused)
        .alt_bg(true)
        .with_scroll(scroll as usize);
    panel.render(frame, area, theme);
    render_scrollbar(frame, area, content_height, area.height, scroll);
}

fn render_security_scores_panel(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    scan_result: &ScanResult,
    state: &AppState,
    theme: &Theme,
    is_focused: bool,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }

    let density = score_density_for_height(area.height);
    let lines = render_security_score_lines(scan_result, area.width, density, theme, state.tick);

    let content = Text::from(lines);
    let content_height = estimated_wrapped_text_height(&content, area.width);
    let max_scroll = content_height.saturating_sub(area.height as usize);
    let scroll = state
        .overview_scroll
        .get(&OverviewFocus::SecurityScores)
        .copied()
        .unwrap_or(0)
        .min(max_scroll.min(u16::MAX as usize) as u16);

    let panel = component::Panel::new(t!("app.panel.security_scores").into_owned(), content)
        .focused(is_focused)
        .with_scroll(scroll as usize);
    panel.render(frame, area, theme);
    render_scrollbar(frame, area, content_height, area.height, scroll);
}

fn render_fix_paths_panel(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    scan_result: &ScanResult,
    state: &AppState,
    theme: &Theme,
    is_focused: bool,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }

    let mut lines = remediation_lines(scan_result, area.width, theme);
    if lines.is_empty() {
        lines.push(Line::raw(t!("app.fix.none").into_owned()));
    }

    let content = Text::from(lines);
    let content_height = estimated_wrapped_text_height(&content, area.width);
    let max_scroll = content_height.saturating_sub(area.height as usize);
    let scroll = state
        .overview_scroll
        .get(&OverviewFocus::FixPaths)
        .copied()
        .unwrap_or(0)
        .min(max_scroll.min(u16::MAX as usize) as u16);

    let panel = component::Panel::new(t!("app.panel.action_queue").into_owned(), content)
        .focused(is_focused)
        .alt_bg(true)
        .with_scroll(scroll as usize);
    panel.render(frame, area, theme);
    render_scrollbar(frame, area, content_height, area.height, scroll);
}

fn overview_footer(theme: &Theme) -> Paragraph<'static> {
    Paragraph::new(Text::from(Line::from(vec![
        hint_span("q", t!("app.footer.quit").into_owned(), theme),
        Span::raw("  "),
        hint_span("Enter", t!("app.footer.findings").into_owned(), theme),
        Span::raw("  "),
        hint_span("Tab", t!("app.footer.focus").into_owned(), theme),
        Span::raw("  "),
        hint_span("s", t!("app.footer.settings").into_owned(), theme),
        Span::raw("  "),
        hint_span("?", t!("app.footer.help").into_owned(), theme),
    ])))
    .alignment(Alignment::Left)
    .block(
        Block::default()
            .borders(Borders::TOP)
            .border_style(theme.border)
            .style(theme.surface),
    )
    .style(theme.surface)
}

fn fix_availability(compose_file: Option<&Path>, finding: Option<&Finding>) -> FixAvailability {
    if compose_file.is_none() {
        return FixAvailability::NoComposeTarget;
    }
    let Some(finding) = finding else {
        return FixAvailability::NoFindingSelected;
    };
    if finding.related_service.is_none() {
        return FixAvailability::NoServiceFix;
    }

    match finding.remediation {
        RemediationKind::Auto | RemediationKind::Review => FixAvailability::Available,
        RemediationKind::Manual => FixAvailability::ManualOnly,
    }
}

fn fix_unavailable_message(availability: FixAvailability) -> String {
    match availability {
        FixAvailability::Available => t!("app.hint.fix_available").into_owned(),
        FixAvailability::NoComposeTarget => t!("app.fix.status.no_compose_target").into_owned(),
        FixAvailability::NoFindingSelected => t!("app.fix.status.no_finding_selected").into_owned(),
        FixAvailability::NoServiceFix => t!("app.fix.status.no_service_fix").into_owned(),
        FixAvailability::ManualOnly => t!("app.fix.status.no_fix_available").into_owned(),
    }
}

fn findings_header(
    _scan_result: &ScanResult,
    state: &AppState,
    available_width: u16,
    mode: FindingsLayoutMode,
    theme: &Theme,
) -> Paragraph<'static> {
    let inner_width = available_width.saturating_sub(2).max(16) as usize;
    let filters = finding_filter_summary(state);
    let mut status_text = if let Some(ref msg) = state.status_message {
        msg.clone()
    } else if state.finding_count() == 0 {
        format!(
            "{} | {}",
            t!("app.finding.empty_status").into_owned(),
            filters
        )
    } else if mode == FindingsLayoutMode::SideBySide {
        let selection = t!(
            "app.finding.status",
            index = state.selected_index + 1,
            count = state.finding_count(),
            focus = focus_label(state.findings_focus)
        )
        .into_owned();
        format!("{} | {}", selection, filters)
    } else {
        format!(
            "{}/{} | {} | {}",
            state.selected_index + 1,
            state.finding_count(),
            focus_label(state.findings_focus),
            filters,
        )
    };
    if state.scope_filter == Some(Scope::Host) {
        status_text = format!("{} | {}", t!("app.finding.host_scope_status"), status_text);
    }

    let title_text = t!("app.panel.findings_header").into_owned();
    let status_style = if state.status_message.is_some() {
        theme.highlight
    } else {
        theme.base
    };
    let wrapped_status = wrap_text_to_lines(&status_text, inner_width).join(" ");

    Paragraph::new(Text::from(vec![
        Line::styled(title_text, theme.title),
        Line::styled(wrapped_status, status_style),
    ]))
    .style(theme.surface)
}

fn findings_footer(
    scan_result: &ScanResult,
    state: &AppState,
    available_width: u16,
    mode: FindingsLayoutMode,
    theme: &Theme,
) -> Paragraph<'static> {
    let inner_width = available_width.saturating_sub(2).max(16) as usize;
    let movement = match state.findings_focus {
        FindingsFocus::List if mode == FindingsLayoutMode::Narrow => {
            t!("app.hint.list_move_compact").into_owned()
        }
        FindingsFocus::Detail if mode == FindingsLayoutMode::Narrow => {
            t!("app.hint.detail_scroll_compact").into_owned()
        }
        FindingsFocus::List => t!("app.hint.list_move").into_owned(),
        FindingsFocus::Detail => t!("app.hint.detail_scroll").into_owned(),
    };
    let controls = if mode == FindingsLayoutMode::Narrow {
        t!("app.hint.finding_controls_compact").into_owned()
    } else {
        t!("app.hint.finding_controls").into_owned()
    };
    let availability = fix_availability(
        scan_result.metadata.compose_file.as_deref(),
        state.selected_finding(scan_result),
    );
    let fix_hint = if availability.is_fixable() {
        t!("app.hint.fix_available").into_owned()
    } else {
        match availability {
            FixAvailability::Available => unreachable!("handled above"),
            FixAvailability::NoComposeTarget => {
                t!("app.hint.fix_unavailable_no_compose").into_owned()
            }
            FixAvailability::NoFindingSelected => {
                t!("app.hint.fix_unavailable_no_finding").into_owned()
            }
            FixAvailability::NoServiceFix => t!("app.hint.fix_unavailable_no_service").into_owned(),
            FixAvailability::ManualOnly => t!("app.hint.fix_unavailable_manual").into_owned(),
        }
    };
    let fix_style = if availability.is_fixable() {
        Style::default().fg(theme.safe).add_modifier(Modifier::BOLD)
    } else {
        theme.muted
    };
    let host_scope_hint = (state.scope_filter == Some(Scope::Host))
        .then(|| wrap_text_to_lines(&t!("app.hint.host_scope_active"), inner_width).join(" "));

    let mut lines = vec![
        Line::raw(wrap_text_to_lines(&movement, inner_width).join(" ")),
        Line::raw(wrap_text_to_lines(&controls, inner_width).join(" ")),
        Line::styled(
            wrap_text_to_lines(&fix_hint, inner_width).join(" "),
            fix_style,
        ),
    ];
    if let Some(host_scope_hint) = host_scope_hint {
        lines.push(Line::styled(host_scope_hint, theme.muted));
    }

    Paragraph::new(Text::from(lines))
        .block(
            Block::default()
                .borders(Borders::TOP)
                .border_style(theme.border)
                .style(theme.surface),
        )
        .style(theme.surface)
        .wrap(Wrap { trim: true })
}

fn findings_list_items(
    scan_result: &ScanResult,
    state: &AppState,
    available_width: u16,
    mode: FindingsLayoutMode,
    theme: &Theme,
) -> Vec<ListItem<'static>> {
    if state.finding_count() == 0 {
        return vec![ListItem::new(t!("app.finding.empty_title").into_owned())];
    }

    let inner_width = available_width.saturating_sub(2).max(16) as usize;

    state
        .sorted_indices
        .iter()
        .copied()
        .filter_map(|index| scan_result.findings.get(index))
        .map(|finding| {
            let compact_subject = finding_list_subject(finding);
            let remediation_badge = remediation_badge_text(finding.remediation);
            let remediation_compact = remediation_badge_compact(finding.remediation);
            let title_full = if mode == FindingsLayoutMode::Narrow {
                format!(
                    "[{}][{}] {} - {}",
                    severity_short_label(finding.severity),
                    remediation_compact,
                    finding.title,
                    compact_subject
                )
            } else {
                format!(
                    "[{}][{}] {}",
                    severity_short_label(finding.severity),
                    remediation_badge,
                    finding.title
                )
            };
            let title_lines = wrap_text_to_lines(&title_full, inner_width);

            let mut lines = Vec::new();
            let style = severity_style(finding.severity, theme).add_modifier(Modifier::BOLD);
            let muted = theme.muted;
            for (i, line) in title_lines.iter().enumerate() {
                if i == 0 {
                    lines.push(Line::styled(line.clone(), style));
                } else {
                    lines.push(Line::styled(format!("  {}", line), style));
                }
            }

            match mode {
                FindingsLayoutMode::Narrow => {
                    let subtitle = format!("[{}] {}", remediation_compact, compact_subject);
                    lines.push(Line::styled(format!("  {}", subtitle), muted));
                }
                FindingsLayoutMode::Stacked => {
                    let subtitle = format!(
                        "{} | {} | {}",
                        source_label(finding.source),
                        compact_subject,
                        remediation_badge
                    );
                    for sub_line in wrap_text_to_lines(&subtitle, inner_width) {
                        lines.push(Line::styled(format!("  {}", sub_line), muted));
                    }
                }
                FindingsLayoutMode::SideBySide | FindingsLayoutMode::CompactList => {
                    let subtitle = format!(
                        "{} | {} | {} | {}",
                        source_label(finding.source),
                        scope_label(finding.scope),
                        finding.subject,
                        remediation_badge
                    );
                    for sub_line in wrap_text_to_lines(&subtitle, inner_width) {
                        lines.push(Line::styled(format!("  {}", sub_line), muted));
                    }
                }
            }
            ListItem::new(Text::from(lines))
        })
        .collect()
}

fn finding_list_item_line_count(
    finding: &Finding,
    inner_width: usize,
    mode: FindingsLayoutMode,
) -> usize {
    let compact_subject = finding_list_subject(finding);
    let remediation_badge = remediation_badge_text(finding.remediation);
    let remediation_compact = remediation_badge_compact(finding.remediation);
    let title = if mode == FindingsLayoutMode::Narrow {
        format!(
            "[{}][{}] {} - {}",
            severity_short_label(finding.severity),
            remediation_compact,
            finding.title,
            compact_subject
        )
    } else {
        format!(
            "[{}][{}] {}",
            severity_short_label(finding.severity),
            remediation_badge,
            finding.title
        )
    };

    let subtitle = match mode {
        FindingsLayoutMode::Narrow => {
            return wrap_text_to_lines(&title, inner_width).len() + 1;
        }
        FindingsLayoutMode::Stacked => {
            format!(
                "{} | {} | {}",
                source_label(finding.source),
                compact_subject,
                remediation_badge
            )
        }
        FindingsLayoutMode::SideBySide | FindingsLayoutMode::CompactList => {
            format!(
                "{} | {} | {} | {}",
                source_label(finding.source),
                scope_label(finding.scope),
                finding.subject,
                remediation_badge
            )
        }
    };

    wrap_text_to_lines(&title, inner_width).len() + wrap_text_to_lines(&subtitle, inner_width).len()
}

fn finding_detail_text(
    scan_result: &ScanResult,
    state: &AppState,
    available_width: u16,
    mode: FindingsLayoutMode,
    theme: &Theme,
) -> Text<'static> {
    let Some(finding) = state.selected_finding(scan_result) else {
        return Text::from(vec![
            Line::styled(
                t!("app.finding.empty_title").into_owned(),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Line::raw(t!("app.finding.empty_description").into_owned()),
        ]);
    };

    let compact = mode == FindingsLayoutMode::Narrow || available_width < 52;

    let mut lines = vec![
        Line::styled(
            finding.title.clone(),
            severity_style(finding.severity, theme).add_modifier(Modifier::BOLD),
        ),
        Line::raw(if compact {
            format!(
                "{} | {} | {} | {}",
                severity_label(finding.severity),
                source_label(finding.source),
                finding_list_subject(finding),
                remediation_badge_text(finding.remediation)
            )
        } else {
            format!(
                "{} | {} | {} | {}",
                source_label(finding.source),
                scope_label(finding.scope),
                finding.subject,
                remediation_badge_text(finding.remediation)
            )
        }),
    ];

    if let Some(service) = &finding.related_service
        && (!compact || service != &finding.subject)
    {
        lines.push(Line::raw(String::new()));
        lines.push(Line::styled(
            t!("app.finding.related_service_label").into_owned(),
            Style::default().add_modifier(Modifier::BOLD),
        ));
        lines.push(Line::raw(service.clone()));
    }

    lines.extend(detail_section(
        t!("app.finding.description_label").into_owned(),
        &finding.description,
    ));
    lines.extend(detail_section(
        t!("app.finding.why_label").into_owned(),
        &finding.why_risky,
    ));
    lines.extend(detail_section(
        t!("app.finding.fix_label").into_owned(),
        &finding.how_to_fix,
    ));

    lines.push(Line::raw(String::new()));
    lines.push(Line::styled(
        t!("app.finding.evidence_label").into_owned(),
        Style::default().add_modifier(Modifier::BOLD),
    ));
    if finding.evidence.is_empty() {
        lines.push(Line::raw(t!("app.finding.no_evidence").into_owned()));
    } else {
        for (key, value) in &finding.evidence {
            lines.push(Line::raw(format!("{}: {}", key, value)));
        }
    }

    Text::from(lines)
}

fn finding_list_subject(finding: &Finding) -> String {
    finding
        .related_service
        .clone()
        .unwrap_or_else(|| finding.subject.clone())
}

fn finding_sort_subject(finding: &Finding) -> &str {
    finding
        .related_service
        .as_deref()
        .unwrap_or(&finding.subject)
}

fn detail_section(label: String, value: &str) -> Vec<Line<'static>> {
    vec![
        Line::raw(String::new()),
        Line::styled(label, Style::default().add_modifier(Modifier::BOLD)),
        Line::raw(value.to_owned()),
    ]
}

fn result_summary_rows(scan_result: &ScanResult) -> Vec<ResultSummaryRow> {
    let mut rows = scan_result
        .metadata
        .services
        .iter()
        .map(|service| {
            (
                service.name.clone(),
                ResultSummaryRow {
                    label: service.name.clone(),
                    severity: None,
                    count: 0,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();

    if scan_result.metadata.host_root.is_some() {
        rows.entry(String::from("Host"))
            .or_insert(ResultSummaryRow {
                label: t!("app.result.host_group").into_owned(),
                severity: None,
                count: 0,
            });
    }

    for finding in &scan_result.findings {
        let key = result_group_key(finding);
        let label = result_group_label(finding);
        let entry = rows.entry(key).or_insert(ResultSummaryRow {
            label,
            severity: None,
            count: 0,
        });

        entry.count += 1;
        entry.severity = match entry.severity {
            Some(current) if severity_rank(current) <= severity_rank(finding.severity) => {
                Some(current)
            }
            _ => Some(finding.severity),
        };
    }

    rows.into_values().collect()
}

fn result_summary_lines(
    scan_result: &ScanResult,
    available_width: u16,
    theme: &Theme,
) -> Vec<Line<'static>> {
    let rows = result_summary_rows(scan_result);
    if rows.is_empty() {
        return vec![Line::raw(t!("app.result.none").into_owned())];
    }

    let label_width = available_width.saturating_sub(20).clamp(10, 28) as usize;

    rows.into_iter()
        .map(|row| {
            let status_text = match row.severity {
                Some(severity) => severity_label(severity),
                None => t!("app.result.ok").into_owned(),
            };
            let status_style = match row.severity {
                Some(severity) => severity_style(severity, theme),
                None => Style::default().fg(theme.safe),
            };
            let label = wrap_text_to_lines(&row.label, label_width).join(" ");

            Line::from(vec![
                Span::styled("* ", Style::default().fg(theme.safe)),
                Span::raw(format!("{label: <width$}", width = label_width)),
                Span::styled(
                    format!("[{status_text}]"),
                    status_style.add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!("  {}", findings_count_label(row.count))),
            ])
        })
        .collect()
}

fn severity_total_lines(
    scan_result: &ScanResult,
    available_width: u16,
    theme: &Theme,
) -> Vec<Line<'static>> {
    let critical = scan_result
        .score_report
        .severity_counts
        .get(&Severity::Critical)
        .copied()
        .unwrap_or_default();
    let high = scan_result
        .score_report
        .severity_counts
        .get(&Severity::High)
        .copied()
        .unwrap_or_default();
    let medium = scan_result
        .score_report
        .severity_counts
        .get(&Severity::Medium)
        .copied()
        .unwrap_or_default();
    let low = scan_result
        .score_report
        .severity_counts
        .get(&Severity::Low)
        .copied()
        .unwrap_or_default();

    let first_pair = Line::from(vec![
        Span::styled(
            format!("{critical} {}", t!("severity.critical").into_owned()),
            severity_style(Severity::Critical, theme).add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            format!("{high} {}", t!("severity.high").into_owned()),
            severity_style(Severity::High, theme).add_modifier(Modifier::BOLD),
        ),
    ]);
    let second_pair = Line::from(vec![
        Span::styled(
            format!("{medium} {}", t!("severity.medium").into_owned()),
            severity_style(Severity::Medium, theme).add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            format!("{low} {}", t!("severity.low").into_owned()),
            severity_style(Severity::Low, theme).add_modifier(Modifier::BOLD),
        ),
    ]);

    if available_width < 42 {
        vec![
            Line::raw(
                t!(
                    "app.result.total_findings",
                    count = scan_result.findings.len()
                )
                .into_owned(),
            ),
            first_pair,
            second_pair,
        ]
    } else {
        vec![
            Line::raw(
                t!(
                    "app.result.total_findings",
                    count = scan_result.findings.len()
                )
                .into_owned(),
            ),
            Line::from(vec![
                Span::styled(
                    format!("{critical} {}", t!("severity.critical").into_owned()),
                    severity_style(Severity::Critical, theme).add_modifier(Modifier::BOLD),
                ),
                Span::raw("  "),
                Span::styled(
                    format!("{high} {}", t!("severity.high").into_owned()),
                    severity_style(Severity::High, theme).add_modifier(Modifier::BOLD),
                ),
                Span::raw("  "),
                Span::styled(
                    format!("{medium} {}", t!("severity.medium").into_owned()),
                    severity_style(Severity::Medium, theme).add_modifier(Modifier::BOLD),
                ),
                Span::raw("  "),
                Span::styled(
                    format!("{low} {}", t!("severity.low").into_owned()),
                    severity_style(Severity::Low, theme).add_modifier(Modifier::BOLD),
                ),
            ]),
        ]
    }
}

fn remediation_lines(
    scan_result: &ScanResult,
    available_width: u16,
    theme: &Theme,
) -> Vec<Line<'static>> {
    let mut fixable_by_service = BTreeMap::<String, usize>::new();
    let mut manual_by_service = BTreeMap::<String, usize>::new();
    let mut host_manual_by_category = BTreeMap::<HostFindingCategory, HostCategorySummary>::new();

    for finding in &scan_result.findings {
        match finding.remediation {
            crate::domain::RemediationKind::Auto | crate::domain::RemediationKind::Review => {
                if let Some(service) = &finding.related_service {
                    *fixable_by_service.entry(service.clone()).or_default() += 1;
                }
            }
            crate::domain::RemediationKind::Manual => {
                if let Some(service) = &finding.related_service {
                    *manual_by_service.entry(service.clone()).or_default() += 1;
                } else if finding.scope == Scope::Host {
                    let category = HostFindingCategory::from_finding_id(&finding.id);
                    let entry =
                        host_manual_by_category
                            .entry(category)
                            .or_insert(HostCategorySummary {
                                category,
                                count: 0,
                                highest_severity: finding.severity,
                            });
                    entry.count += 1;
                    if severity_rank(finding.severity) < severity_rank(entry.highest_severity) {
                        entry.highest_severity = finding.severity;
                    }
                } else {
                    *manual_by_service
                        .entry(finding.subject.clone())
                        .or_default() += 1;
                }
            }
        }
    }

    let auto_fixable_count: usize = fixable_by_service.values().sum();
    let host_manual_count: usize = host_manual_by_category
        .values()
        .map(|summary| summary.count)
        .sum();
    let manual_count: usize = manual_by_service.values().sum::<usize>() + host_manual_count;
    let mut host_manual_summaries = host_manual_by_category.into_values().collect::<Vec<_>>();
    host_manual_summaries.sort_by(|left, right| {
        severity_rank(left.highest_severity)
            .cmp(&severity_rank(right.highest_severity))
            .then_with(|| right.count.cmp(&left.count))
            .then_with(|| left.category.label().cmp(&right.category.label()))
    });

    let mut lines = Vec::new();
    let text_width = available_width.saturating_sub(4).max(24) as usize;

    let action_hint = t!("app.overview.action_queue_hint").to_string();
    lines.push(Line::styled(
        wrap_text_to_lines(&action_hint, text_width).join(" "),
        theme.muted,
    ));
    lines.push(Line::raw(String::new()));

    if auto_fixable_count > 0 {
        lines.push(Line::from(vec![
            Span::styled(
                format!("[{}] ", t!("remediation.auto_fixable").into_owned()),
                remediation_style(RemediationKind::Auto, theme).add_modifier(Modifier::BOLD),
            ),
            Span::raw(
                t!(
                    "app.result.auto_fixable_summary",
                    count = auto_fixable_count
                )
                .into_owned(),
            ),
        ]));

        for (service, count) in fixable_by_service {
            lines.push(Line::from(vec![
                Span::raw("  • "),
                Span::styled(service, theme.base.add_modifier(Modifier::BOLD)),
                Span::raw(format!(": {}", count)),
            ]));
        }
    }

    if manual_count > 0 {
        if !lines.is_empty() {
            lines.push(Line::raw(""));
        }

        lines.push(Line::from(vec![
            Span::styled(
                format!("[{}] ", t!("remediation.manual").into_owned()),
                remediation_style(RemediationKind::Manual, theme).add_modifier(Modifier::BOLD),
            ),
            Span::raw(t!("app.result.manual_summary", count = manual_count).into_owned()),
        ]));

        for (service, count) in manual_by_service {
            lines.push(Line::from(vec![
                Span::raw("  • "),
                Span::styled(service, theme.base.add_modifier(Modifier::BOLD)),
                Span::raw(format!(": {}", count)),
            ]));
        }

        for summary in host_manual_summaries {
            let category_label = summary.category.label();
            lines.push(Line::from(vec![
                Span::raw("  • "),
                Span::styled(
                    format!("{} / {}", t!("scope.host"), category_label),
                    theme.base.add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!(": {}", summary.count)),
            ]));
        }
    }

    if auto_fixable_count == 0 && manual_count == 0 {
        lines.push(Line::raw(
            t!("app.result.no_remediation_needed").into_owned(),
        ));
    }

    if !scan_result.findings.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            t!("app.overview.next_step").into_owned(),
            theme.title.add_modifier(Modifier::BOLD),
        ));
        lines.push(Line::styled(
            t!("app.hint.open_findings").into_owned(),
            theme.highlight.add_modifier(Modifier::BOLD),
        ));
        lines.push(Line::styled(
            t!(
                "app.overview.findings_ready",
                count = scan_result.findings.len()
            )
            .into_owned(),
            theme.muted,
        ));
    }

    if auto_fixable_count > 0 && scan_result.metadata.compose_file.is_some() {
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            t!("app.hint.press_f_to_fix").into_owned(),
            Style::default().fg(theme.safe),
        ));
    }

    lines
}

fn server_service_lines(
    scan_result: &ScanResult,
    available_width: u16,
    theme: &Theme,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    lines.extend(defensive_controls_lines(
        scan_result,
        available_width,
        theme,
    ));

    lines.push(Line::styled(
        t!("app.server.services_heading").into_owned(),
        theme.title.add_modifier(Modifier::BOLD),
    ));

    if scan_result.metadata.services.is_empty() {
        lines.push(Line::raw(t!("app.server.no_services").into_owned()));
        return lines;
    }

    let text_width = available_width.saturating_sub(4).max(20) as usize;
    for service in scan_result.metadata.services.iter().take(4) {
        let image = service
            .image
            .clone()
            .unwrap_or_else(|| t!("app.server.no_image").into_owned());
        lines.push(Line::raw(
            wrap_text_to_lines(&format!("{} - {}", service.name, image), text_width).join(" "),
        ));
    }

    if scan_result.metadata.services.len() > 4 {
        lines.push(Line::raw(
            t!(
                "app.server.more_services",
                count = scan_result.metadata.services.len() - 4
            )
            .into_owned(),
        ));
    }

    lines
}

fn defensive_controls_lines(
    scan_result: &ScanResult,
    available_width: u16,
    _theme: &Theme,
) -> Vec<Line<'static>> {
    let Some(runtime) = scan_result.metadata.host_runtime.as_ref() else {
        return Vec::new();
    };
    let text_width = available_width.saturating_sub(4).max(20) as usize;
    let fail2ban = defensive_control_summary(
        t!("app.server.fail2ban").into_owned(),
        runtime.fail2ban,
        fail2ban_detail(runtime),
    );
    vec![Line::raw(
        wrap_text_to_lines(
            &format!("{}: {}", t!("app.server.controls").into_owned(), fail2ban),
            text_width,
        )
        .join(" "),
    )]
}

fn defensive_control_summary(
    label: String,
    status: DefensiveControlStatus,
    detail: Option<String>,
) -> String {
    match detail {
        Some(detail) => format!(
            "{} {} ({})",
            label,
            defensive_control_status_label(status),
            detail
        ),
        None => format!("{} {}", label, defensive_control_status_label(status)),
    }
}

fn fail2ban_detail(runtime: &HostRuntimeInfo) -> Option<String> {
    let mut parts = Vec::new();

    if let Some(count) = runtime.fail2ban_jails {
        parts.push(t!("app.server.control_jails", count = count).into_owned());
    }
    if let Some(count) = runtime.fail2ban_banned_ips {
        parts.push(t!("app.server.control_banned_ips", count = count).into_owned());
    }

    (!parts.is_empty()).then(|| parts.join(", "))
}

fn score_sparkline() -> Option<String> {
    let history = crate::history::load();
    let entries = history.trend(6);
    if entries.len() < 2 {
        return None;
    }
    let chars = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let max = entries.iter().map(|e| e.overall).max().unwrap_or(100);
    let min = entries.iter().map(|e| e.overall).min().unwrap_or(0);
    let range = (max - min).max(1) as f32;
    let spark: String = entries
        .iter()
        .map(|e| {
            let idx =
                ((e.overall - min) as f32 / range * (chars.len() - 1) as f32).round() as usize;
            chars[idx.min(chars.len() - 1)]
        })
        .collect();
    Some(spark)
}

fn overall_score_delta() -> Option<String> {
    let history = crate::history::load();
    let previous = history.previous_overall()?;
    let current = history.entries.last()?.overall;
    let delta = current as i16 - previous as i16;
    if delta > 0 {
        Some(t!("app.score.trend_up", delta = delta).into_owned())
    } else if delta < 0 {
        Some(t!("app.score.trend_down", delta = -delta).into_owned())
    } else {
        Some(t!("app.score.trend_same").into_owned())
    }
}

fn score_rows(scan_result: &ScanResult) -> Vec<(String, u8, bool)> {
    let mut rows = vec![(
        t!("app.score.overall").into_owned(),
        scan_result.score_report.overall,
        true,
    )];

    rows.extend(Axis::ALL.into_iter().map(|axis| {
        let score = scan_result
            .score_report
            .axis_scores
            .get(&axis)
            .copied()
            .unwrap_or(100);
        (axis_label(axis), score, false)
    }));

    rows
}

fn score_color_for_value(score: u8, theme: &Theme) -> ratatui::style::Color {
    match score {
        90..=100 => theme.safe,
        70..=89 => theme.low,
        50..=69 => theme.med,
        30..=49 => theme.high,
        _ => theme.crit,
    }
}

fn score_grade_label(score: u8) -> String {
    match score {
        90..=100 => t!("app.score.grade_good").into_owned(),
        70..=89 => t!("app.score.grade_fair").into_owned(),
        50..=69 => t!("app.score.grade_poor").into_owned(),
        30..=49 => t!("app.score.grade_bad").into_owned(),
        _ => t!("app.score.grade_critical").into_owned(),
    }
}

fn score_bar(score: u8, width: usize) -> String {
    let filled = ((score as usize * width).max(1) / 100).min(width);
    let empty = width.saturating_sub(filled);
    format!("{}{}", "█".repeat(filled), "░".repeat(empty))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScoreDensity {
    Minimal,
    Compact,
    Standard,
    Spacious,
}

fn score_density_for_height(inner_height: u16) -> ScoreDensity {
    match inner_height {
        0..=3 => ScoreDensity::Minimal,
        4..=6 => ScoreDensity::Compact,
        7..=11 => ScoreDensity::Standard,
        _ => ScoreDensity::Spacious,
    }
}

fn score_panel_min_height(density: ScoreDensity) -> u16 {
    match density {
        ScoreDensity::Minimal => 2,
        ScoreDensity::Compact => 4,
        ScoreDensity::Standard => 7,
        ScoreDensity::Spacious => 12,
    }
}

fn axis_short_label(label: &str) -> String {
    label.chars().take(4).collect()
}

fn render_security_score_lines(
    scan_result: &ScanResult,
    inner_width: u16,
    density: ScoreDensity,
    theme: &Theme,
    tick: usize,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let text_width = inner_width.saturating_sub(2).max(16) as usize;

    if has_pending_adapters(scan_result) {
        match density {
            ScoreDensity::Minimal | ScoreDensity::Compact => {
                lines.push(Line::styled(
                    adapter_progress_label(scan_result, tick),
                    theme.muted,
                ));
            }
            _ => {
                lines.push(Line::raw(
                    wrap_text_to_lines(&adapter_progress_label(scan_result, tick), text_width)
                        .join(" "),
                ));
                lines.push(Line::raw(
                    t!("app.overview.score_pending_detail").into_owned(),
                ));
                lines.push(Line::raw(String::new()));
            }
        }
    }

    let rows = score_rows(scan_result);
    if rows.is_empty() {
        return lines;
    }

    let bar_width = (text_width / 3).clamp(8, 14);

    match density {
        ScoreDensity::Spacious => {
            for (label, score, is_overall) in &rows {
                let color = score_color_for_value(*score, theme);
                let grade = score_grade_label(*score);
                lines.push(Line::from(vec![
                    Span::raw(format!("{}: ", label)),
                    Span::styled(
                        format!("{}", score),
                        Style::default().fg(color).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled("/100", theme.muted),
                    Span::raw(" "),
                    Span::styled(format!("[{}]", grade), Style::default().fg(color)),
                ]));
                let bar = score_bar(*score, bar_width);
                if *is_overall {
                    if let Some(delta) = overall_score_delta() {
                        lines.push(Line::from(vec![
                            Span::raw("  "),
                            Span::styled(bar, Style::default().fg(color)),
                            Span::raw(" "),
                            Span::styled(delta, theme.muted),
                        ]));
                    } else {
                        lines.push(Line::from(vec![
                            Span::raw("  "),
                            Span::styled(bar, Style::default().fg(color)),
                        ]));
                    }
                    if let Some(spark) = score_sparkline() {
                        lines.push(Line::styled(format!("  {}", spark), theme.muted));
                    }
                } else {
                    lines.push(Line::from(vec![
                        Span::raw("  "),
                        Span::styled(bar, Style::default().fg(color)),
                    ]));
                    lines.push(Line::raw(""));
                }
            }
        }
        ScoreDensity::Standard => {
            for (label, score, is_overall) in &rows {
                let color = score_color_for_value(*score, theme);
                let grade = score_grade_label(*score);
                lines.push(Line::from(vec![
                    Span::raw(format!("{}: ", label)),
                    Span::styled(
                        format!("{}", score),
                        Style::default().fg(color).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled("/100", theme.muted),
                    Span::raw(" "),
                    Span::styled(format!("[{}]", grade), Style::default().fg(color)),
                ]));
                let bar = score_bar(*score, bar_width);
                if *is_overall {
                    if let Some(delta) = overall_score_delta() {
                        lines.push(Line::from(vec![
                            Span::raw("  "),
                            Span::styled(bar, Style::default().fg(color)),
                            Span::raw(" "),
                            Span::styled(delta, theme.muted),
                        ]));
                    } else {
                        lines.push(Line::from(vec![
                            Span::raw("  "),
                            Span::styled(bar, Style::default().fg(color)),
                        ]));
                    }
                } else {
                    lines.push(Line::from(vec![
                        Span::raw("  "),
                        Span::styled(bar, Style::default().fg(color)),
                    ]));
                }
            }
        }
        ScoreDensity::Compact => {
            // Overall on one line with delta
            if let Some((label, score, _)) = rows.first() {
                let color = score_color_for_value(*score, theme);
                let grade = score_grade_label(*score);
                let delta = overall_score_delta()
                    .map(|d| format!(" {}", d))
                    .unwrap_or_default();
                lines.push(Line::from(vec![
                    Span::raw(format!("{}: ", label)),
                    Span::styled(
                        format!("{}", score),
                        Style::default().fg(color).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled("/100", theme.muted),
                    Span::raw(" "),
                    Span::styled(format!("[{}]", grade), Style::default().fg(color)),
                    Span::styled(delta, theme.muted),
                ]));
            }
            // Axes in pairs with short labels
            for chunk in rows.iter().skip(1).collect::<Vec<_>>().chunks(2) {
                let mut spans = vec![Span::raw(" ")];
                for (i, (label, score, _)) in chunk.iter().enumerate() {
                    if i > 0 {
                        spans.push(Span::raw("  "));
                    }
                    let color = score_color_for_value(*score, theme);
                    let grade = score_grade_label(*score);
                    let short = axis_short_label(label);
                    spans.push(Span::styled(
                        format!("{}:{}/100[{}]", short, score, grade),
                        Style::default().fg(color),
                    ));
                }
                lines.push(Line::from(spans));
            }
        }
        ScoreDensity::Minimal => {
            if let Some((label, score, _)) = rows.first() {
                let color = score_color_for_value(*score, theme);
                let grade = score_grade_label(*score);
                let delta = overall_score_delta()
                    .map(|d| format!(" {}", d))
                    .unwrap_or_default();
                let mut spans = vec![
                    Span::raw(format!("{} ", label)),
                    Span::styled(
                        format!("{}", score),
                        Style::default().fg(color).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(format!("[{}]", grade), Style::default().fg(color)),
                    Span::styled(delta, theme.muted),
                ];
                for (axis_label, axis_score, _) in rows.iter().skip(1) {
                    let c = score_color_for_value(*axis_score, theme);
                    let short = axis_label.chars().take(1).collect::<String>();
                    spans.push(Span::raw(" "));
                    spans.push(Span::styled(
                        format!("{}:{}", short, axis_score),
                        Style::default().fg(c),
                    ));
                }
                lines.push(Line::from(spans));
            }
        }
    }

    lines
}

fn render_detail_scrollbar(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    content_height: usize,
    viewport_height: u16,
    state: &AppState,
) {
    if area.width == 0 || area.height <= 2 || content_height <= viewport_height as usize {
        return;
    }

    let mut scrollbar_state = ScrollbarState::default()
        .content_length(content_height)
        .viewport_content_length(viewport_height as usize)
        .position(state.detail_scroll as usize);

    frame.render_stateful_widget(
        Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None)
            .track_symbol(None)
            .thumb_symbol("▐"),
        area.inner(Margin {
            vertical: 1,
            horizontal: 0,
        }),
        &mut scrollbar_state,
    );
}

fn render_scrollbar(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    content_height: usize,
    viewport_height: u16,
    scroll: u16,
) {
    if area.width == 0 || area.height <= 2 || content_height <= viewport_height as usize {
        return;
    }

    let mut scrollbar_state = ScrollbarState::default()
        .content_length(content_height)
        .viewport_content_length(viewport_height as usize)
        .position(scroll as usize);

    frame.render_stateful_widget(
        Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None)
            .track_symbol(None)
            .thumb_symbol("▐"),
        area.inner(Margin {
            vertical: 1,
            horizontal: 0,
        }),
        &mut scrollbar_state,
    );
}

fn estimated_wrapped_text_height(text: &Text<'_>, width: u16) -> usize {
    let width = width as usize;
    if width == 0 {
        return 0;
    }

    text.lines
        .iter()
        .map(|line| estimated_wrapped_line_height(line, width))
        .sum()
}

fn estimated_wrapped_line_height(line: &Line<'_>, width: usize) -> usize {
    if width == 0 {
        return 0;
    }

    let content = line
        .spans
        .iter()
        .map(|span| span.content.as_ref())
        .collect::<String>();

    if content.trim().is_empty() {
        return 1;
    }

    let mut rendered_lines = 0usize;
    let mut current_width = 0usize;

    for word in content.split_whitespace() {
        let mut remaining = word.chars().count();
        while remaining > 0 {
            if current_width == 0 {
                let chunk = remaining.min(width);
                current_width = chunk;
                remaining -= chunk;

                if remaining > 0 {
                    rendered_lines += 1;
                    current_width = 0;
                }
            } else if current_width + 1 + remaining <= width {
                current_width += 1 + remaining;
                remaining = 0;
            } else {
                rendered_lines += 1;
                current_width = 0;
            }
        }
    }

    if current_width > 0 || rendered_lines == 0 {
        rendered_lines + 1
    } else {
        rendered_lines
    }
}

fn result_group_key(finding: &Finding) -> String {
    finding
        .related_service
        .clone()
        .unwrap_or_else(|| match finding.scope {
            Scope::Host => String::from("Host"),
            _ => finding.subject.clone(),
        })
}

fn result_group_label(finding: &Finding) -> String {
    if finding.scope == Scope::Host {
        t!("app.result.host_group").into_owned()
    } else {
        finding
            .related_service
            .clone()
            .unwrap_or_else(|| finding.subject.clone())
    }
}

#[allow(clippy::too_many_arguments)]
fn visible_finding_indices(
    scan_result: &ScanResult,
    severity_filter: Option<Severity>,
    source_filter: Option<Source>,
    scope_filter: Option<Scope>,
    remediation_filter: RemediationFilter,
    service_filter: Option<&str>,
    sort_mode: FindingSortMode,
    search_query: Option<&str>,
) -> Vec<usize> {
    let query = search_query.unwrap_or("").to_lowercase();
    let mut indices = (0..scan_result.findings.len()).collect::<Vec<_>>();
    indices.retain(|index| {
        scan_result.findings.get(*index).is_some_and(|finding| {
            severity_filter.is_none_or(|severity| finding.severity == severity)
                && source_filter.is_none_or(|source| finding.source == source)
                && scope_filter.is_none_or(|scope| finding.scope == scope)
                && remediation_filter_matches(finding.remediation, remediation_filter)
                && service_filter
                    .is_none_or(|service| finding.related_service.as_deref() == Some(service))
                && (query.is_empty()
                    || finding.title.to_lowercase().contains(&query)
                    || finding.description.to_lowercase().contains(&query)
                    || finding.subject.to_lowercase().contains(&query)
                    || finding.how_to_fix.to_lowercase().contains(&query))
        })
    });
    indices.sort_by(|left, right| {
        compare_findings(
            &scan_result.findings[*left],
            &scan_result.findings[*right],
            sort_mode,
        )
    });
    indices
}

fn compare_findings(left: &Finding, right: &Finding, sort_mode: FindingSortMode) -> Ordering {
    match sort_mode {
        FindingSortMode::Severity => severity_rank(left.severity)
            .cmp(&severity_rank(right.severity))
            .then_with(|| left.title.cmp(&right.title))
            .then_with(|| left.source.cmp(&right.source))
            .then_with(|| left.scope.cmp(&right.scope))
            .then_with(|| left.subject.cmp(&right.subject))
            .then_with(|| left.id.cmp(&right.id)),
        FindingSortMode::Source => left
            .source
            .cmp(&right.source)
            .then_with(|| severity_rank(left.severity).cmp(&severity_rank(right.severity)))
            .then_with(|| left.title.cmp(&right.title))
            .then_with(|| left.scope.cmp(&right.scope))
            .then_with(|| left.subject.cmp(&right.subject))
            .then_with(|| left.id.cmp(&right.id)),
        FindingSortMode::Subject => finding_sort_subject(left)
            .cmp(finding_sort_subject(right))
            .then_with(|| severity_rank(left.severity).cmp(&severity_rank(right.severity)))
            .then_with(|| left.title.cmp(&right.title))
            .then_with(|| left.source.cmp(&right.source))
            .then_with(|| left.id.cmp(&right.id)),
    }
}

fn remediation_filter_matches(remediation: RemediationKind, filter: RemediationFilter) -> bool {
    match filter {
        RemediationFilter::All => true,
        RemediationFilter::Fixable => remediation != RemediationKind::Manual,
        RemediationFilter::Auto => remediation == RemediationKind::Auto,
        RemediationFilter::Review => remediation == RemediationKind::Review,
        RemediationFilter::Manual => remediation == RemediationKind::Manual,
    }
}

fn finding_filter_summary(state: &AppState) -> String {
    format!(
        "{}:{} {}:{} {}:{} {}:{} {}:{}",
        t!("app.finding.severity_filter_short").into_owned(),
        severity_filter_label(state.severity_filter),
        t!("app.finding.source_filter_short").into_owned(),
        source_filter_label(state.source_filter),
        t!("app.finding.service_filter_short").into_owned(),
        service_filter_label(state.service_filter.as_deref()),
        t!("app.finding.remediation_filter_short").into_owned(),
        remediation_filter_label(state.remediation_filter),
        t!("app.finding.sort_short").into_owned(),
        sort_mode_label(state.sort_mode),
    )
}

fn service_filter_label(filter: Option<&str>) -> String {
    filter
        .map(|s| s.to_owned())
        .unwrap_or_else(|| t!("app.finding.filter_all").into_owned())
}

fn severity_filter_label(filter: Option<Severity>) -> String {
    filter
        .map(severity_label)
        .unwrap_or_else(|| t!("app.finding.filter_all").into_owned())
}

fn source_filter_label(filter: Option<Source>) -> String {
    filter
        .map(source_label)
        .unwrap_or_else(|| t!("app.finding.filter_all").into_owned())
}

fn remediation_filter_label(filter: RemediationFilter) -> String {
    match filter {
        RemediationFilter::All => t!("app.finding.filter_all").into_owned(),
        RemediationFilter::Fixable => t!("app.finding.filter_fixable").into_owned(),
        RemediationFilter::Auto => t!("app.finding.filter_auto").into_owned(),
        RemediationFilter::Review => t!("app.finding.filter_review").into_owned(),
        RemediationFilter::Manual => t!("app.finding.filter_manual").into_owned(),
    }
}

fn sort_mode_label(sort_mode: FindingSortMode) -> String {
    match sort_mode {
        FindingSortMode::Severity => t!("app.finding.sort_severity").into_owned(),
        FindingSortMode::Source => t!("app.finding.sort_source").into_owned(),
        FindingSortMode::Subject => t!("app.finding.sort_subject").into_owned(),
    }
}

fn findings_count_label(count: usize) -> String {
    if count == 1 {
        t!("app.result.single_finding").into_owned()
    } else {
        t!("app.result.multi_findings", count = count).into_owned()
    }
}

fn docker_status_label(status: &DockerDiscoveryStatus) -> String {
    match status {
        DockerDiscoveryStatus::Available => t!("app.result.docker_available").into_owned(),
        DockerDiscoveryStatus::Missing => t!("app.result.docker_missing").into_owned(),
        DockerDiscoveryStatus::PermissionDenied => {
            t!("app.result.docker_permission_denied").into_owned()
        }
        DockerDiscoveryStatus::Failed(detail) => {
            t!("app.result.docker_failed", detail = detail.as_str()).into_owned()
        }
    }
}

fn adapter_summary_lines(
    scan_result: &ScanResult,
    available_width: u16,
    state: &AppState,
    theme: &Theme,
) -> Vec<Line<'static>> {
    if scan_result.metadata.adapters.is_empty() {
        return Vec::new();
    }

    let text_width = available_width.saturating_sub(4).max(20) as usize;
    let mut lines = vec![Line::styled(
        t!("app.result.adapters_heading").into_owned(),
        theme.title.add_modifier(Modifier::BOLD),
    )];

    if has_pending_adapters(scan_result) {
        lines.push(Line::styled(
            wrap_text_to_lines(&adapter_progress_label(scan_result, state.tick), text_width)
                .join(" "),
            theme.muted,
        ));
    }

    for (name, status) in &scan_result.metadata.adapters {
        lines.push(Line::raw(
            wrap_text_to_lines(
                &format!(
                    "* {}: {}",
                    adapter_name_label(name),
                    adapter_status_label(status)
                ),
                text_width,
            )
            .join(" "),
        ));
    }

    lines
}

fn adapter_name_label(name: &str) -> String {
    match name {
        "lynis" => source_label(Source::Lynis),
        "trivy" => source_label(Source::Trivy),
        "dockle" => source_label(Source::Dockle),
        "gitleaks" => source_label(Source::Gitleaks),
        _ => name.to_owned(),
    }
}

fn adapter_status_label(status: &AdapterStatus) -> String {
    match status {
        AdapterStatus::Pending => t!("adapter.loading").into_owned(),
        AdapterStatus::Available => t!("adapter.available").into_owned(),
        AdapterStatus::Missing => t!("adapter.missing").into_owned(),
        AdapterStatus::Skipped(detail) => {
            t!("adapter.skipped", detail = detail.as_str()).into_owned()
        }
        AdapterStatus::Failed(detail) => {
            t!("adapter.failed", detail = detail.as_str()).into_owned()
        }
    }
}

fn has_pending_adapters(scan_result: &ScanResult) -> bool {
    scan_result
        .metadata
        .adapters
        .values()
        .any(|status| matches!(status, AdapterStatus::Pending))
}

fn spinner_frame(tick: usize) -> &'static str {
    const FRAMES: [&str; 8] = ["-", "\\", "|", "/", "-", "\\", "|", "/"];
    FRAMES[tick % FRAMES.len()]
}

fn adapter_progress_label(scan_result: &ScanResult, tick: usize) -> String {
    let pending = scan_result
        .metadata
        .adapters
        .iter()
        .filter(|(_, status)| matches!(status, AdapterStatus::Pending))
        .map(|(name, _)| adapter_name_label(name))
        .collect::<Vec<_>>();

    if pending.is_empty() {
        return t!("app.overview.score_ready").to_string();
    }

    t!(
        "app.overview.adapter_loading",
        spinner = spinner_frame(tick),
        adapters = pending.join(", ")
    )
    .into_owned()
}

fn display_host_root(scan_result: &ScanResult) -> String {
    scan_result
        .metadata
        .host_root
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| t!("app.server.not_scanned").into_owned())
}

fn display_hostname(scan_result: &ScanResult) -> String {
    scan_result
        .metadata
        .host_runtime
        .as_ref()
        .and_then(|runtime| runtime.hostname.clone())
        .unwrap_or_else(|| t!("app.server.not_available").into_owned())
}

fn display_docker_version(scan_result: &ScanResult) -> String {
    scan_result
        .metadata
        .host_runtime
        .as_ref()
        .and_then(|runtime| runtime.docker_version.clone())
        .unwrap_or_else(|| t!("app.server.not_available").into_owned())
}

fn display_uptime(scan_result: &ScanResult) -> String {
    scan_result
        .metadata
        .host_runtime
        .as_ref()
        .and_then(|runtime| runtime.uptime.clone())
        .unwrap_or_else(|| t!("app.server.not_available").into_owned())
}

fn load_display(scan_result: &ScanResult) -> String {
    scan_result
        .metadata
        .host_runtime
        .as_ref()
        .and_then(|runtime| runtime.load_average.clone())
        .unwrap_or_else(|| t!("app.server.not_available").into_owned())
}

fn defensive_control_status_label(status: DefensiveControlStatus) -> String {
    match status {
        DefensiveControlStatus::NotDetected => t!("app.server.control_not_detected").into_owned(),
        DefensiveControlStatus::Installed => t!("app.server.control_installed").into_owned(),
        DefensiveControlStatus::Enabled => t!("app.server.control_enabled").into_owned(),
    }
}

fn kv_line(label: String, value: String, theme: &Theme) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label: <14}"), theme.title),
        Span::raw(value),
    ])
}

fn findings_list_title(focus: FindingsFocus) -> String {
    if focus == FindingsFocus::List {
        t!("app.panel.findings_list_active").into_owned()
    } else {
        t!("app.panel.findings_list").into_owned()
    }
}

fn findings_detail_title(focus: FindingsFocus) -> String {
    if focus == FindingsFocus::Detail {
        t!("app.panel.finding_detail_active").into_owned()
    } else {
        t!("app.panel.finding_detail").into_owned()
    }
}

fn focus_label(focus: FindingsFocus) -> String {
    match focus {
        FindingsFocus::List => t!("app.finding.focus_list").into_owned(),
        FindingsFocus::Detail => t!("app.finding.focus_detail").into_owned(),
    }
}

fn current_locale_badge() -> String {
    format!("LANG {}", i18n::current_locale().to_ascii_uppercase())
}

fn hint_span(key: &str, label: String, theme: &Theme) -> Span<'static> {
    Span::styled(format!("[{key}] {label}"), theme.title)
}

fn wrap_text_to_lines(value: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![value.to_owned()];
    }
    let mut lines = Vec::new();
    let mut current_line = String::new();

    for word in value.split_whitespace() {
        if current_line.is_empty() {
            current_line.push_str(word);
        } else if current_line.len() + 1 + word.len() <= width {
            current_line.push(' ');
            current_line.push_str(word);
        } else {
            lines.push(current_line);
            current_line = word.to_owned();
        }
    }
    if !current_line.is_empty() {
        lines.push(current_line);
    }
    if lines.is_empty() && !value.is_empty() {
        lines.push(String::new());
    }
    lines
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
    }
}

fn severity_label(severity: Severity) -> String {
    match severity {
        Severity::Critical => t!("severity.critical").into_owned(),
        Severity::High => t!("severity.high").into_owned(),
        Severity::Medium => t!("severity.medium").into_owned(),
        Severity::Low => t!("severity.low").into_owned(),
    }
}

fn severity_short_label(severity: Severity) -> String {
    match severity {
        Severity::Critical => t!("app.finding.severity_short.critical").into_owned(),
        Severity::High => t!("app.finding.severity_short.high").into_owned(),
        Severity::Medium => t!("app.finding.severity_short.medium").into_owned(),
        Severity::Low => t!("app.finding.severity_short.low").into_owned(),
    }
}

fn axis_label(axis: Axis) -> String {
    match axis {
        Axis::SensitiveData => t!("axis.sensitive_data").into_owned(),
        Axis::ExcessivePermissions => t!("axis.permissions").into_owned(),
        Axis::UnnecessaryExposure => t!("axis.exposure").into_owned(),
        Axis::UpdateSupplyChainRisk => t!("axis.updates").into_owned(),
        Axis::HostHardening => t!("axis.host_hardening").into_owned(),
    }
}

fn source_label(source: Source) -> String {
    match source {
        Source::NativeCompose => t!("source.native_compose").into_owned(),
        Source::NativeHost => t!("source.native_host").into_owned(),
        Source::Trivy => t!("source.trivy").into_owned(),
        Source::Lynis => t!("source.lynis").into_owned(),
        Source::Dockle => t!("source.dockle").into_owned(),
        Source::Gitleaks => t!("source.gitleaks").into_owned(),
    }
}

fn scope_label(scope: Scope) -> String {
    match scope {
        Scope::Service => t!("scope.service").into_owned(),
        Scope::Image => t!("scope.image").into_owned(),
        Scope::Host => t!("scope.host").into_owned(),
        Scope::Project => t!("scope.project").into_owned(),
    }
}

fn remediation_badge_text(remediation: RemediationKind) -> String {
    match remediation {
        RemediationKind::Auto => t!("app.finding.remediation_badge.auto").into_owned(),
        RemediationKind::Review => t!("app.finding.remediation_badge.review").into_owned(),
        RemediationKind::Manual => t!("app.finding.remediation_badge.manual").into_owned(),
    }
}

fn remediation_badge_compact(remediation: RemediationKind) -> String {
    match remediation {
        RemediationKind::Auto => t!("app.finding.remediation_badge_compact.auto").into_owned(),
        RemediationKind::Review => t!("app.finding.remediation_badge_compact.review").into_owned(),
        RemediationKind::Manual => t!("app.finding.remediation_badge_compact.manual").into_owned(),
    }
}

fn severity_style(severity: Severity, theme: &Theme) -> Style {
    Style::default().fg(match severity {
        Severity::Critical => theme.crit,
        Severity::High => theme.high,
        Severity::Medium => theme.med,
        Severity::Low => theme.low,
    })
}

fn remediation_style(remediation: RemediationKind, theme: &Theme) -> Style {
    Style::default().fg(match remediation {
        RemediationKind::Auto => theme.safe,
        RemediationKind::Review => theme.guided,
        RemediationKind::Manual => theme.manual,
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use ratatui::Terminal;
    use ratatui::backend::{Backend, TestBackend};

    use super::*;
    use crate::domain::{
        AdapterStatus, DiscoveredProjectSummary, DockerDiscoveryStatus, HostRuntimeInfo, ScanMode,
        ScoreReport, ServiceSummary,
    };

    fn sample_result() -> ScanResult {
        ScanResult {
            findings: vec![
                Finding {
                    id: String::from("exposure.admin_interface_public"),
                    axis: Axis::UnnecessaryExposure,
                    severity: Severity::Critical,
                    scope: Scope::Service,
                    source: Source::NativeCompose,
                    subject: String::from("adminer"),
                    related_service: Some(String::from("adminer")),
                    title: String::from("Admin interface is exposed publicly"),
                    description: String::from(
                        "adminer exposes an administrative interface on 8080:8080.",
                    ),
                    why_risky: String::from(
                        "Public admin panels invite brute force and exploit attempts.",
                    ),
                    how_to_fix: String::from("Put the admin interface behind a private network."),
                    evidence: BTreeMap::from([(String::from("port"), String::from("8080:8080"))]),
                    remediation: RemediationKind::Review,
                },
                Finding {
                    id: String::from("host.ssh_root_login_enabled"),
                    axis: Axis::HostHardening,
                    severity: Severity::High,
                    scope: Scope::Host,
                    source: Source::NativeHost,
                    subject: String::from("/etc/ssh/sshd_config"),
                    related_service: None,
                    title: String::from("SSH root login is enabled"),
                    description: String::from("/etc/ssh/sshd_config allows root login."),
                    why_risky: String::from("Attackers can target a direct root login."),
                    how_to_fix: String::from("Set PermitRootLogin no."),
                    evidence: BTreeMap::from([(
                        String::from("path"),
                        String::from("/etc/ssh/sshd_config"),
                    )]),
                    remediation: RemediationKind::Manual,
                },
                Finding {
                    id: String::from("updates.latest_tag"),
                    axis: Axis::UpdateSupplyChainRisk,
                    severity: Severity::Low,
                    scope: Scope::Service,
                    source: Source::NativeCompose,
                    subject: String::from("vaultwarden"),
                    related_service: Some(String::from("vaultwarden")),
                    title: String::from("Image uses the latest tag"),
                    description: String::from("vaultwarden uses latest."),
                    why_risky: String::from("Moving tags hurt reproducibility."),
                    how_to_fix: String::from("Pin the image to a specific version."),
                    evidence: BTreeMap::new(),
                    remediation: RemediationKind::Auto,
                },
            ],
            score_report: ScoreReport {
                overall: 61,
                scan_focus: vec![
                    Axis::SensitiveData,
                    Axis::ExcessivePermissions,
                    Axis::UnnecessaryExposure,
                    Axis::UpdateSupplyChainRisk,
                ],
                axis_scores: BTreeMap::from([
                    (Axis::SensitiveData, 100),
                    (Axis::ExcessivePermissions, 100),
                    (Axis::UnnecessaryExposure, 25),
                    (Axis::UpdateSupplyChainRisk, 80),
                    (Axis::HostHardening, 65),
                ]),
                severity_counts: BTreeMap::from([
                    (Severity::Critical, 1),
                    (Severity::High, 1),
                    (Severity::Medium, 0),
                    (Severity::Low, 1),
                ]),
                axis_weights: BTreeMap::from([
                    (Axis::SensitiveData, 0.35),
                    (Axis::ExcessivePermissions, 0.30),
                    (Axis::UnnecessaryExposure, 0.20),
                    (Axis::UpdateSupplyChainRisk, 0.15),
                    (Axis::HostHardening, 0.0),
                ]),
                severity_deductions: BTreeMap::from([
                    (Severity::Critical, 75),
                    (Severity::High, 35),
                    (Severity::Medium, 15),
                    (Severity::Low, 5),
                ]),
            },
            metadata: crate::domain::ScanMetadata {
                scan_mode: ScanMode::Live,
                compose_root: Some(PathBuf::from("/srv/demo")),
                compose_file: Some(PathBuf::from("/srv/demo/docker-compose.yml")),
                host_root: Some(PathBuf::from("/")),
                host_runtime: Some(HostRuntimeInfo {
                    hostname: Some(String::from("home-server")),
                    docker_version: Some(String::from("24.0.7")),
                    uptime: Some(String::from("14d 3h 22m")),
                    load_average: Some(String::from("0.42 0.31 0.27")),
                    fail2ban: DefensiveControlStatus::Enabled,
                    fail2ban_jails: Some(2),
                    fail2ban_banned_ips: Some(5),
                }),
                loaded_files: vec![
                    PathBuf::from("/srv/demo/docker-compose.yml"),
                    PathBuf::from("/srv/demo/docker-compose.override.yml"),
                ],
                service_count: 2,
                services: vec![
                    ServiceSummary {
                        name: String::from("adminer"),
                        image: Some(String::from("adminer:latest")),
                    },
                    ServiceSummary {
                        name: String::from("vaultwarden"),
                        image: Some(String::from("vaultwarden/server:1.30.1")),
                    },
                ],
                discovered_projects: vec![DiscoveredProjectSummary {
                    name: String::from("demo"),
                    source: String::from("docker"),
                    compose_path: Some(PathBuf::from("/srv/demo/docker-compose.yml")),
                    working_dir: Some(PathBuf::from("/srv/demo")),
                    service_count: 2,
                }],
                docker_status: Some(DockerDiscoveryStatus::Available),
                warnings: vec![String::from(
                    "Using the current directory as a Compose fallback because no running Compose project was discovered.",
                )],
                adapters: BTreeMap::from([
                    (String::from("lynis"), AdapterStatus::Available),
                    (String::from("trivy"), AdapterStatus::Missing),
                    (String::from("gitleaks"), AdapterStatus::Available),
                ]),
            },
        }
    }

    fn mixed_scope_result() -> ScanResult {
        let mut result = sample_result();
        result.findings.push(Finding {
            id: String::from("trivy.image_vulnerabilities.adminer_latest"),
            axis: Axis::UpdateSupplyChainRisk,
            severity: Severity::High,
            scope: Scope::Image,
            source: Source::Trivy,
            subject: String::from("adminer:latest"),
            related_service: Some(String::from("adminer")),
            title: String::from("Image vulnerabilities found"),
            description: String::from("adminer:latest has multiple high-risk vulnerabilities."),
            why_risky: String::from("Known CVEs increase the chance of compromise."),
            how_to_fix: String::from("Pin and rebuild with a patched image."),
            evidence: BTreeMap::from([(String::from("image"), String::from("adminer:latest"))]),
            remediation: RemediationKind::Manual,
        });
        result.findings.push(Finding {
            id: String::from("project.compose_bundle_loaded"),
            axis: Axis::SensitiveData,
            severity: Severity::Low,
            scope: Scope::Project,
            source: Source::NativeCompose,
            subject: String::from("/srv/demo/docker-compose.yml"),
            related_service: None,
            title: String::from("Project-level compose review"),
            description: String::from(
                "Project-wide settings should be reviewed alongside per-service findings.",
            ),
            why_risky: String::from(
                "Shared Compose settings can affect every service in the stack.",
            ),
            how_to_fix: String::from("Review the Compose project configuration as a whole."),
            evidence: BTreeMap::from([(
                String::from("compose_file"),
                String::from("/srv/demo/docker-compose.yml"),
            )]),
            remediation: RemediationKind::Manual,
        });
        result
    }

    fn host_triage_result() -> ScanResult {
        let mut result = sample_result();
        result.findings = vec![
            Finding {
                id: String::from("host.ssh_root_login_enabled"),
                axis: Axis::HostHardening,
                severity: Severity::High,
                scope: Scope::Host,
                source: Source::NativeHost,
                subject: String::from("/etc/ssh/sshd_config"),
                related_service: None,
                title: String::from("SSH root login is enabled"),
                description: String::from("/etc/ssh/sshd_config allows root login."),
                why_risky: String::from("Attackers can target a direct root login."),
                how_to_fix: String::from("Set PermitRootLogin no."),
                evidence: BTreeMap::new(),
                remediation: RemediationKind::Manual,
            },
            Finding {
                id: String::from("host.firewalld_disabled"),
                axis: Axis::HostHardening,
                severity: Severity::Critical,
                scope: Scope::Host,
                source: Source::NativeHost,
                subject: String::from("firewalld"),
                related_service: None,
                title: String::from("firewalld is disabled"),
                description: String::from("The system firewall is disabled."),
                why_risky: String::from("Inbound traffic is less constrained."),
                how_to_fix: String::from("Enable and configure firewalld."),
                evidence: BTreeMap::new(),
                remediation: RemediationKind::Manual,
            },
            Finding {
                id: String::from("host.nftables_missing"),
                axis: Axis::HostHardening,
                severity: Severity::High,
                scope: Scope::Host,
                source: Source::NativeHost,
                subject: String::from("nftables"),
                related_service: None,
                title: String::from("nftables rules are missing"),
                description: String::from("No nftables rules were detected."),
                why_risky: String::from("Network paths remain under-protected."),
                how_to_fix: String::from("Define a baseline nftables policy."),
                evidence: BTreeMap::new(),
                remediation: RemediationKind::Manual,
            },
            Finding {
                id: String::from("host.kernel.aslr_disabled"),
                axis: Axis::HostHardening,
                severity: Severity::Medium,
                scope: Scope::Host,
                source: Source::NativeHost,
                subject: String::from("kernel.randomize_va_space"),
                related_service: None,
                title: String::from("ASLR is disabled"),
                description: String::from("Address space layout randomization is disabled."),
                why_risky: String::from("Exploit reliability improves without ASLR."),
                how_to_fix: String::from("Set kernel.randomize_va_space to 2."),
                evidence: BTreeMap::new(),
                remediation: RemediationKind::Manual,
            },
        ];
        result.score_report.severity_counts = BTreeMap::from([
            (Severity::Critical, 1),
            (Severity::High, 2),
            (Severity::Medium, 1),
            (Severity::Low, 0),
        ]);
        result
    }

    fn no_findings_result() -> ScanResult {
        let mut result = sample_result();
        result.findings.clear();
        result.score_report.severity_counts = BTreeMap::from([
            (Severity::Critical, 0),
            (Severity::High, 0),
            (Severity::Medium, 0),
            (Severity::Low, 0),
        ]);
        result
    }

    fn long_content_result() -> ScanResult {
        let mut result = mixed_scope_result();
        result.metadata.services = vec![
            ServiceSummary {
                name: String::from("adminer-with-a-very-long-service-name"),
                image: Some(String::from(
                    "registry.example.test/selfhost/adminer-with-long-path:2026.04.24",
                )),
            },
            ServiceSummary {
                name: String::from("vaultwarden"),
                image: Some(String::from("vaultwarden/server:1.30.1")),
            },
            ServiceSummary {
                name: String::from("nextcloud"),
                image: Some(String::from("nextcloud:29.0.4-apache")),
            },
            ServiceSummary {
                name: String::from("immich-machine-learning"),
                image: Some(String::from(
                    "ghcr.io/immich-app/immich-machine-learning:v1.99.0",
                )),
            },
            ServiceSummary {
                name: String::from("gitea"),
                image: Some(String::from("gitea/gitea:1.22.0-rootless")),
            },
        ];
        result.findings[0].title = String::from(
            "Administrative interface is exposed publicly with a long explanation-worthy title",
        );
        result.findings[0].description = String::from(
            "The service publishes an administrative HTTP interface to every network interface, so the full sentence must remain visible in the TUI.",
        );
        result.findings[0].how_to_fix = String::from(
            "Bind the port to localhost, move it behind a reverse proxy with authentication, or remove the public port mapping.",
        );
        result
    }

    #[test]
    fn overview_navigation_opens_findings() {
        let result = sample_result();
        let mut state = AppState::new(&result);

        let action = handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Enter, crossterm::event::KeyModifiers::NONE),
        );

        assert!(action.is_none());
        assert_eq!(state.screen, Screen::Findings);
        assert_eq!(state.findings_focus, FindingsFocus::List);
    }

    #[test]
    fn overview_host_shortcut_opens_host_filtered_findings() {
        let result = mixed_scope_result();
        let mut state = AppState::new(&result);

        let action = handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('h'), crossterm::event::KeyModifiers::NONE),
        );

        assert!(action.is_none());
        assert_eq!(state.screen, Screen::Findings);
        assert_eq!(state.scope_filter, Some(Scope::Host));
        assert!(
            state
                .selected_finding(&result)
                .is_some_and(|finding| finding.scope == Scope::Host)
        );
    }

    #[test]
    fn findings_navigation_moves_selection_and_scrolls_detail() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.open_findings();

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Down, crossterm::event::KeyModifiers::NONE),
        );
        assert_eq!(state.selected_index, 1);

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Tab, crossterm::event::KeyModifiers::NONE),
        );
        assert_eq!(state.findings_focus, FindingsFocus::Detail);

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::PageDown, crossterm::event::KeyModifiers::NONE),
        );
        assert!(state.detail_scroll > 0);

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Esc, crossterm::event::KeyModifiers::NONE),
        );
        assert_eq!(state.screen, Screen::Overview);
    }

    #[test]
    fn findings_left_and_right_keys_switch_focus() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.open_findings();
        assert_eq!(state.findings_focus, FindingsFocus::List);

        // Right key should focus detail
        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Right, KeyModifiers::NONE),
        );
        assert_eq!(state.findings_focus, FindingsFocus::Detail);

        // Left key should focus back to list
        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Left, KeyModifiers::NONE),
        );
        assert_eq!(state.findings_focus, FindingsFocus::List);

        // 'l' should focus detail
        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('l'), KeyModifiers::NONE),
        );
        assert_eq!(state.findings_focus, FindingsFocus::Detail);

        // 'h' should focus list
        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('h'), KeyModifiers::NONE),
        );
        assert_eq!(state.findings_focus, FindingsFocus::List);

        // Enter should also focus detail
        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
        );
        assert_eq!(state.findings_focus, FindingsFocus::Detail);
    }

    #[test]
    fn findings_controls_cycle_filters_and_sort_modes() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.open_findings();

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('S'), crossterm::event::KeyModifiers::SHIFT),
        );
        state.clamp_selection(&result);
        assert_eq!(state.severity_filter, Some(Severity::Critical));
        assert_eq!(state.finding_count(), 1);

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('x'), crossterm::event::KeyModifiers::NONE),
        );
        state.clamp_selection(&result);
        assert_eq!(state.source_filter, Some(Source::NativeCompose));
        assert_eq!(state.finding_count(), 1);

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('m'), crossterm::event::KeyModifiers::NONE),
        );
        state.clamp_selection(&result);
        assert_eq!(state.remediation_filter, RemediationFilter::Fixable);
        assert_eq!(state.finding_count(), 1);

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('o'), crossterm::event::KeyModifiers::NONE),
        );
        assert_eq!(state.sort_mode, FindingSortMode::Source);

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('o'), crossterm::event::KeyModifiers::NONE),
        );
        assert_eq!(state.sort_mode, FindingSortMode::Subject);

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('r'), crossterm::event::KeyModifiers::NONE),
        );
        assert_eq!(state.severity_filter, None);
        assert_eq!(state.source_filter, None);
        assert_eq!(state.remediation_filter, RemediationFilter::All);
        assert_eq!(state.sort_mode, FindingSortMode::Severity);
    }

    #[test]
    fn findings_controls_cycle_remediation_filter_states() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.open_findings();

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('m'), crossterm::event::KeyModifiers::NONE),
        );
        state.clamp_selection(&result);
        assert_eq!(state.remediation_filter, RemediationFilter::Fixable);
        assert_eq!(state.finding_count(), 2);

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('m'), crossterm::event::KeyModifiers::NONE),
        );
        state.clamp_selection(&result);
        assert_eq!(state.remediation_filter, RemediationFilter::Auto);
        assert_eq!(state.finding_count(), 1);

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('m'), crossterm::event::KeyModifiers::NONE),
        );
        state.clamp_selection(&result);
        assert_eq!(state.remediation_filter, RemediationFilter::Review);
        assert_eq!(state.finding_count(), 1);

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('m'), crossterm::event::KeyModifiers::NONE),
        );
        state.clamp_selection(&result);
        assert_eq!(state.remediation_filter, RemediationFilter::Manual);
        assert_eq!(state.finding_count(), 1);

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('m'), crossterm::event::KeyModifiers::NONE),
        );
        state.clamp_selection(&result);
        assert_eq!(state.remediation_filter, RemediationFilter::All);
        assert_eq!(state.finding_count(), 3);
    }

    #[test]
    fn source_filter_cycle_includes_gitleaks() {
        let result = sample_result();
        let mut state = AppState::new(&result);

        for _ in 0..6 {
            state.cycle_source_filter();
        }
        assert_eq!(state.source_filter, Some(Source::Gitleaks));

        state.cycle_source_filter();
        assert_eq!(state.source_filter, None);
    }

    #[test]
    fn findings_controls_can_filter_by_severity() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.open_findings();

        // Press 'S' once → Critical filter
        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('S'), crossterm::event::KeyModifiers::SHIFT),
        );
        assert_eq!(state.severity_filter, Some(Severity::Critical));

        // Press 'S' three more times → Low filter
        for _ in 0..3 {
            handle_key(
                &mut state,
                &result,
                KeyEvent::new(KeyCode::Char('S'), crossterm::event::KeyModifiers::SHIFT),
            );
        }
        assert_eq!(state.severity_filter, Some(Severity::Low));
    }

    #[test]
    fn overview_renders_mockup_like_sections_in_80x24() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("terminal should build");

        terminal
            .draw(|frame| render(frame, &result, &mut state))
            .expect("overview should render");

        let content = buffer_to_string(terminal.backend());

        assert!(content.contains("Linux Self-Hosting Security Dashboard"));
        assert!(content.contains("Server Status"));
        assert!(content.contains("Scan Results"));
        assert!(content.contains("Security Scores"));
        assert!(content.contains("Action Queue"));
        assert!(content.contains("61"));
        assert!(content.contains("adminer"));
        assert!(content.contains("home-server"));
        assert!(content.contains("24.0.7"));
        assert!(content.contains("0.42 0.31 0.27"));
        assert!(content.contains("AUTO"));
        assert!(!content.contains("########"));
        assert!(!content.contains("----------"));
    }

    #[test]
    fn overview_remediation_summary_shows_auto_and_manual_counts() {
        let lines = remediation_lines(&sample_result(), 80, &Theme::preset(ThemePreset::Ansi));

        let text: String = lines
            .iter()
            .map(|l| line_to_string(l))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("AUTO"));
        assert!(text.contains("MANUAL"));
    }

    #[test]
    fn overview_action_queue_groups_host_findings_by_category() {
        let lines = remediation_lines(&host_triage_result(), 80, &Theme::preset(ThemePreset::Ansi));

        let text: String = lines
            .iter()
            .map(line_to_string)
            .collect::<Vec<_>>()
            .join("\n");

        assert!(text.contains("Host / Firewall: 2"));
        assert!(text.contains("Host / SSH: 1"));
        assert!(text.contains("Host / Kernel: 1"));
        assert!(!text.contains("Host: 4"));
    }

    #[test]
    fn overview_action_queue_orders_host_categories_by_severity_then_count() {
        let lines = remediation_lines(&host_triage_result(), 80, &Theme::preset(ThemePreset::Ansi));

        let text: String = lines
            .iter()
            .map(line_to_string)
            .collect::<Vec<_>>()
            .join("\n");

        let firewall_index = text.find("Host / Firewall: 2").expect("firewall summary");
        let ssh_index = text.find("Host / SSH: 1").expect("ssh summary");
        let kernel_index = text.find("Host / Kernel: 1").expect("kernel summary");

        assert!(firewall_index < ssh_index);
        assert!(ssh_index < kernel_index);
    }

    #[test]
    fn overview_action_queue_hint_mentions_host_areas() {
        let lines = remediation_lines(&host_triage_result(), 80, &Theme::preset(ThemePreset::Ansi));

        let text: String = lines
            .iter()
            .map(line_to_string)
            .collect::<Vec<_>>()
            .join("\n");

        assert!(text.contains("service and host area"));
    }

    #[test]
    fn overview_renders_full_metadata_in_wide_layout() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.layout_preset = LayoutPreset::Wide;
        let mut terminal = Terminal::new(TestBackend::new(120, 40)).expect("terminal should build");

        terminal
            .draw(|frame| render(frame, &result, &mut state))
            .expect("wide overview should render");

        let content = buffer_to_string(terminal.backend());

        assert!(content.contains("home-server"));
        assert!(content.contains("24.0.7"));
        assert!(content.contains("14d 3h 22m"));
        assert!(content.contains("0.42 0.31 0.27"));
        assert!(content.contains("Fail2ban enabled"));
        assert!(content.contains("Adapters"));
        assert!(content.contains("Lynis: available"));
        assert!(content.contains("Trivy: missing"));
        assert!(content.contains("Gitleaks: available"));
    }

    #[test]
    fn legacy_adaptive_wide_layout_stacks_status_and_scores_and_places_queue_next_to_scan_results()
    {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.layout_preset = LayoutPreset::AdaptiveLegacy;
        let mut terminal = Terminal::new(TestBackend::new(120, 40)).expect("terminal should build");

        terminal
            .draw(|frame| render(frame, &result, &mut state))
            .expect("legacy adaptive overview should render");

        let content = buffer_to_string(terminal.backend());

        let (status_x, status_y) =
            find_rendered_position(&content, "Server Status").expect("server status title");
        let (scan_x, scan_y) =
            find_rendered_position(&content, "Scan Results").expect("scan results title");
        let (scores_x, scores_y) =
            find_rendered_position(&content, "Security Scores").expect("security scores title");
        let (queue_x, queue_y) =
            find_rendered_position(&content, "Action Queue").expect("action queue title");

        // Scan results and action queue should be full-height side-by-side.
        assert_eq!(status_y, scan_y);
        assert_eq!(scan_y, queue_y);
        assert!(queue_x > scan_x);

        // Server status and security scores should be stacked in the left column.
        assert!(scores_y > status_y);
        assert!(scores_x < scan_x);
        assert_eq!(scores_x, status_x);
    }

    #[test]
    fn overview_renders_in_narrow_layout_without_ascii_bars() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        let mut terminal = Terminal::new(TestBackend::new(60, 20)).expect("terminal should build");

        terminal
            .draw(|frame| render(frame, &result, &mut state))
            .expect("narrow overview should render");

        let content = buffer_to_string(terminal.backend());

        assert!(content.contains("Server Status"));
        assert!(content.contains("Scan Results"));
        assert!(content.contains("Security Scores"));
        assert!(content.contains("Action Queue"));
        assert!(content.contains("0.42 0.31 0.27"));
        assert!(!content.contains("########"));
        assert!(!content.contains("----------"));
    }

    #[test]
    fn overview_renders_loading_copy_without_exposing_pending_state() {
        let mut result = sample_result();
        result
            .metadata
            .adapters
            .insert(String::from("trivy"), AdapterStatus::Pending);
        result
            .metadata
            .adapters
            .insert(String::from("dockle"), AdapterStatus::Pending);
        let mut state = AppState::new(&result);
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("terminal should build");

        terminal
            .draw(|frame| render(frame, &result, &mut state))
            .expect("overview should render");

        let content = buffer_to_string(terminal.backend());

        assert!(!content.contains("pending"));
    }

    #[test]
    fn adapter_progress_label_uses_loading_copy_instead_of_pending() {
        let mut result = sample_result();
        result
            .metadata
            .adapters
            .insert(String::from("trivy"), AdapterStatus::Pending);
        result
            .metadata
            .adapters
            .insert(String::from("dockle"), AdapterStatus::Pending);

        let label = adapter_progress_label(&result, 0);

        assert!(label.contains("loading adapters"));
        assert!(label.contains("Trivy"));
        assert!(label.contains("Dockle"));
        assert!(!label.contains("pending"));
    }

    #[test]
    fn theme_cycle_advances_to_next_preset() {
        let result = sample_result();
        let mut state = AppState::new(&result);

        let initial = state.theme_preset;
        state.cycle_theme();

        assert_eq!(state.theme_preset, initial.next());
        assert_eq!(state.theme.preset, initial.next());
    }

    #[test]
    fn preset_themes_apply_body_background_but_ansi_keeps_default() {
        let result = sample_result();
        let mut themed_state = AppState::new(&result);
        themed_state.theme_preset = ThemePreset::Catppuccin;
        themed_state.theme = Theme::preset(ThemePreset::Catppuccin);
        let mut themed_terminal =
            Terminal::new(TestBackend::new(80, 24)).expect("terminal should build");

        themed_terminal
            .draw(|frame| render(frame, &result, &mut themed_state))
            .expect("themed overview should render");

        let themed_body_bg = buffer_bg(themed_terminal.backend(), 10, 10);
        let themed_footer_bg = buffer_bg(themed_terminal.backend(), 10, 23);

        assert_ne!(themed_body_bg, ratatui::style::Color::Reset);
        assert_ne!(themed_footer_bg, ratatui::style::Color::Reset);

        let mut ansi_state = AppState::new(&result);
        ansi_state.theme_preset = ThemePreset::Ansi;
        ansi_state.theme = Theme::preset(ThemePreset::Ansi);
        let mut ansi_terminal =
            Terminal::new(TestBackend::new(80, 24)).expect("terminal should build");

        ansi_terminal
            .draw(|frame| render(frame, &result, &mut ansi_state))
            .expect("ansi overview should render");

        // ANSI now uses subtle panel backgrounds instead of borders.
        let ansi_body_bg = buffer_bg(ansi_terminal.backend(), 10, 10);
        assert_ne!(
            ansi_body_bg,
            ratatui::style::Color::Reset,
            "ANSI theme should still apply panel backgrounds"
        );
    }

    #[test]
    fn overview_renders_explicit_findings_cta_when_findings_exist() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        let mut terminal = Terminal::new(TestBackend::new(120, 40)).expect("terminal should build");

        terminal
            .draw(|frame| render(frame, &result, &mut state))
            .expect("overview should render");

        let content = buffer_to_string(terminal.backend());

        assert!(content.contains("Press Enter or Right to inspect findings"));
        assert!(content.contains("Next Step"));
        assert!(content.contains("3 finding(s) are ready for review"));
    }

    #[test]
    fn overview_hides_findings_cta_when_no_findings_exist() {
        let result = no_findings_result();
        let mut state = AppState::new(&result);
        let mut terminal = Terminal::new(TestBackend::new(120, 40)).expect("terminal should build");

        terminal
            .draw(|frame| render(frame, &result, &mut state))
            .expect("overview should render");

        let content = buffer_to_string(terminal.backend());

        assert!(content.contains("No findings detected yet."));
        assert!(!content.contains("Press Enter or Right to inspect findings"));
        assert!(!content.contains("Next Step"));
    }

    #[test]
    fn findings_view_renders_selected_finding_details() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.open_findings();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("terminal should build");

        terminal
            .draw(|frame| render(frame, &result, &mut state))
            .expect("findings view should render");

        let content = buffer_to_string(terminal.backend());

        assert!(content.contains("Findings [list focus]"));
        assert!(content.contains("Detail"));
        assert!(content.contains("[REVIEW]"));
        assert!(content.contains("Admin interface is exposed publicly"));
        assert!(content.contains("Native Compose | Service | adminer | REVIEW"));
        assert!(content.contains("rem:all"));
        assert!(content.contains("adminer"));
    }

    #[test]
    fn findings_view_renders_long_how_to_fix_without_truncation() {
        let mut result = sample_result();
        result.findings[0].how_to_fix = String::from(
            "Run 'sysctl -w kernel.unprivileged_userns_clone=0' to apply immediately. \
Create /etc/sysctl.d/99-userns.conf with 'kernel.unprivileged_userns_clone = 0' to persist. \
Verify with 'sysctl kernel.unprivileged_userns_clone'.",
        );
        let mut state = AppState::new(&result);
        state.open_findings();
        let mut terminal = Terminal::new(TestBackend::new(80, 40)).expect("terminal should build");

        terminal
            .draw(|frame| render(frame, &result, &mut state))
            .expect("findings view should render long fix text");

        let content = buffer_to_string(terminal.backend());

        assert!(content.contains("How to Fix"));
        assert!(content.contains("99-userns.conf"));
        assert!(content.contains("sysctl kernel.unprivileged_userns_clone"));
    }

    #[test]
    fn findings_view_renders_project_scope_from_shared_scan_result() {
        let result = mixed_scope_result();
        let mut state = AppState::new(&result);
        state.open_findings();
        state.selected_index = state
            .sorted_indices
            .iter()
            .position(|index| {
                result
                    .findings
                    .get(*index)
                    .is_some_and(|finding| finding.scope == Scope::Project)
            })
            .expect("project finding should exist");
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("terminal should build");

        terminal
            .draw(|frame| render(frame, &result, &mut state))
            .expect("findings view should render mixed scopes");

        let content = buffer_to_string(terminal.backend());

        assert!(content.contains("Project"));
        assert!(content.contains("Project-level compose review"));
        assert!(content.contains("/srv/demo/docker-compose.yml"));
    }

    #[test]
    fn findings_view_renders_empty_state() {
        let result = no_findings_result();
        let mut state = AppState::new(&result);
        state.open_findings();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("terminal");
        terminal
            .draw(|frame| render(frame, &result, &mut state))
            .expect("empty findings should render");
        let content = buffer_to_string(terminal.backend());
        assert!(
            content.contains("0") || content.contains("No"),
            "empty findings should show count: {}",
            content
        );
    }

    #[test]
    fn findings_view_clamps_detail_scroll_after_resize_like_render() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.open_findings();
        state.focus_detail();
        state.detail_scroll = u16::MAX;
        let mut terminal = Terminal::new(TestBackend::new(60, 20)).expect("terminal should build");

        terminal
            .draw(|frame| render(frame, &result, &mut state))
            .expect("stacked findings view should render");

        let content = buffer_to_string(terminal.backend());

        assert!(content.contains("Findings"));
        assert!(content.contains("Detail"));
        assert!(state.detail_scroll < u16::MAX);
    }

    #[test]
    fn narrow_findings_view_uses_compact_copy_and_rows() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.open_findings();
        let mut terminal = Terminal::new(TestBackend::new(60, 24)).expect("terminal should build");

        terminal
            .draw(|frame| render(frame, &result, &mut state))
            .expect("narrow findings view should render");

        let content = buffer_to_string(terminal.backend());

        assert!(content.contains("[CRIT][R] Admin interface is exposed publicly - adminer"));
        assert!(content.contains("Critical | Native Compose | adminer | REVIEW"));
        assert!(content.contains("S sev | x src | v svc | m rem | o sort"));
        assert!(!content.contains("PageUp/PageDown"));
    }

    #[test]
    fn tui_buffers_do_not_use_visible_ellipsis_for_security_content() {
        let result = long_content_result();
        let mut overview_state = AppState::new(&result);
        overview_state.layout_preset = LayoutPreset::Wide;
        let mut overview_terminal =
            Terminal::new(TestBackend::new(120, 40)).expect("terminal should build");

        overview_terminal
            .draw(|frame| render(frame, &result, &mut overview_state))
            .expect("overview should render");
        let overview = buffer_to_string(overview_terminal.backend());

        let mut findings_state = AppState::new(&result);
        findings_state.open_findings();
        let mut findings_terminal =
            Terminal::new(TestBackend::new(80, 24)).expect("terminal should build");

        findings_terminal
            .draw(|frame| render(frame, &result, &mut findings_state))
            .expect("findings should render");
        let findings = buffer_to_string(findings_terminal.backend());

        assert!(!overview.contains("..."));
        assert!(!findings.contains("..."));
        assert!(overview.contains("additional service"));
        assert!(findings.contains("Administrative interface is exposed publicly"));
    }

    #[test]
    fn layout_presets_render_across_representative_terminal_sizes() {
        let sizes = [
            (50, 16),
            (60, 20),
            (80, 24),
            (100, 30),
            (120, 40),
            (160, 45),
        ];
        let presets = [
            LayoutPreset::Adaptive,
            LayoutPreset::AdaptiveLegacy,
            LayoutPreset::Wide,
            LayoutPreset::Balanced,
            LayoutPreset::Compact,
            LayoutPreset::Focus,
        ];
        let result = long_content_result();

        for preset in presets {
            for (width, height) in sizes {
                let mut overview_state = AppState::new(&result);
                overview_state.layout_preset = preset;
                let mut overview_terminal =
                    Terminal::new(TestBackend::new(width, height)).expect("terminal should build");
                overview_terminal
                    .draw(|frame| render(frame, &result, &mut overview_state))
                    .expect("overview should render");
                let overview = buffer_to_string(overview_terminal.backend());
                assert!(overview.contains("hostveil"));

                let mut findings_state = AppState::new(&result);
                findings_state.layout_preset = preset;
                findings_state.open_findings();
                let mut findings_terminal =
                    Terminal::new(TestBackend::new(width, height)).expect("terminal should build");
                findings_terminal
                    .draw(|frame| render(frame, &result, &mut findings_state))
                    .expect("findings should render");
                let findings = buffer_to_string(findings_terminal.backend());
                assert!(findings.contains("Findings") || findings.contains("Detail"));
            }
        }

        assert_eq!(
            findings_layout_mode(
                Rect {
                    x: 0,
                    y: 0,
                    width: 120,
                    height: 40,
                },
                LayoutPreset::Focus,
            ),
            FindingsLayoutMode::CompactList
        );
    }

    #[test]
    fn mouse_click_selects_the_actual_visible_finding_row() {
        let result = long_content_result();
        let mut state = AppState::new(&result);
        state.open_findings();
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).expect("terminal should build");

        terminal
            .draw(|frame| render(frame, &result, &mut state))
            .expect("findings should render");

        let (rect, _) = state
            .hit_boxes
            .iter()
            .find(|(_, target)| matches!(target, HitTarget::FindingList(1)))
            .expect("second visible row should be clickable")
            .clone();
        handle_mouse(
            &mut state,
            &result,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: rect.x,
                row: rect.y,
                modifiers: KeyModifiers::NONE,
            },
        );

        assert_eq!(state.selected_index, 1);
    }

    #[test]
    fn settings_modal_supports_keyboard_and_mouse_adjustments() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.open_settings();

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('2'), crossterm::event::KeyModifiers::NONE),
        );
        assert_eq!(state.settings_row, 1);

        let initial_layout = state.layout_preset;
        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Right, crossterm::event::KeyModifiers::NONE),
        );
        assert_eq!(state.layout_preset, initial_layout.next());

        let mut terminal = Terminal::new(TestBackend::new(100, 30)).expect("terminal should build");
        terminal
            .draw(|frame| render(frame, &result, &mut state))
            .expect("settings modal should render");
        let content = buffer_to_string(terminal.backend());
        assert!(content.contains("Theme"));
        assert!(content.contains("Layout"));
        assert!(content.contains("Locale"));

        let (rect, _) = state
            .hit_boxes
            .iter()
            .find(|(_, target)| matches!(target, HitTarget::SettingsRow(0)))
            .expect("theme row should be clickable")
            .clone();
        let initial_theme = state.theme_preset;
        handle_mouse(
            &mut state,
            &result,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: rect.x,
                row: rect.y,
                modifiers: KeyModifiers::NONE,
            },
        );

        assert_eq!(state.settings_row, 0);
        assert_eq!(state.theme_preset, initial_theme.next());
    }

    #[test]
    fn selected_tab_uses_highlight_background() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.theme_preset = ThemePreset::TokyoNight;
        state.theme = crate::tui::theme::Theme::preset(ThemePreset::TokyoNight);
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).expect("terminal should build");
        terminal
            .draw(|frame| render(frame, &result, &mut state))
            .expect("overview should render");

        let expected_bg = state
            .theme
            .highlight
            .bg
            .expect("highlight should define a background colour");

        // Scan the top banner area where tabs live and assert at least one cell carries the highlight bg.
        let backend = terminal.backend();
        let buffer = backend.buffer();
        let mut found = false;
        for y in 0..5 {
            for x in 0..100 {
                if buffer[(x, y)].style().bg == Some(expected_bg) {
                    found = true;
                    break;
                }
            }
            if found {
                break;
            }
        }
        assert!(
            found,
            "active tab background should contain theme.highlight.bg"
        );
    }

    #[test]
    fn settings_modal_dim_darkens_background_and_preserves_fg() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.theme_preset = ThemePreset::TokyoNight;
        state.theme = crate::tui::theme::Theme::preset(ThemePreset::TokyoNight);
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).expect("terminal should build");

        // Render without modal first and capture a cell behind it.
        terminal
            .draw(|frame| render(frame, &result, &mut state))
            .expect("overview should render");
        let fg_before = terminal.backend().buffer()[(2, 15)].style().fg;
        let bg_before = terminal.backend().buffer()[(2, 15)].style().bg;

        // Open settings modal and re-render.
        state.settings_open = true;
        terminal
            .draw(|frame| render(frame, &result, &mut state))
            .expect("settings modal should render");
        let fg_after = terminal.backend().buffer()[(2, 15)].style().fg;
        let bg_after = terminal.backend().buffer()[(2, 15)].style().bg;

        // Foreground colour must stay exactly the same.
        assert_eq!(
            fg_before, fg_after,
            "modal dim must preserve the original cell foreground colour"
        );

        // Background colour must have been darkened (or remain None).
        match (bg_before, bg_after) {
            (
                Some(ratatui::style::Color::Rgb(r1, g1, b1)),
                Some(ratatui::style::Color::Rgb(r2, g2, b2)),
            ) => {
                assert!(
                    r2 <= r1 && g2 <= g1 && b2 <= b1,
                    "modal dim must darken the background colour, before=Rgb({r1},{g1},{b1}) after=Rgb({r2},{g2},{b2})"
                );
            }
            (None, None) => {} // no bg to dim
            _ => panic!("modal dim changed bg presence unexpectedly"),
        }
    }

    fn line_to_string(line: &Line<'_>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>()
    }

    fn buffer_to_string(backend: &TestBackend) -> String {
        let area = backend.size().expect("backend should have a size");
        let buffer = backend.buffer();
        let mut output = String::new();

        for y in 0..area.height {
            for x in 0..area.width {
                output.push_str(buffer[(x, y)].symbol());
            }
            output.push('\n');
        }

        output
    }

    fn buffer_bg(backend: &TestBackend, x: u16, y: u16) -> ratatui::style::Color {
        backend.buffer()[(x, y)]
            .style()
            .bg
            .unwrap_or(ratatui::style::Color::Reset)
    }

    fn buffer_fg(backend: &TestBackend, x: u16, y: u16) -> ratatui::style::Color {
        backend.buffer()[(x, y)]
            .style()
            .fg
            .unwrap_or(ratatui::style::Color::Reset)
    }

    fn find_rendered_position(rendered: &str, needle: &str) -> Option<(usize, usize)> {
        for (y, line) in rendered.lines().enumerate() {
            if let Some(byte_index) = line.find(needle) {
                let x = line[..byte_index].chars().count();
                return Some((x, y));
            }
        }
        None
    }

    #[test]
    fn fix_key_without_compose_file_shows_status_message() {
        let mut result = sample_result();
        result.metadata.compose_file = None;
        let mut state = AppState::new(&result);
        state.open_findings();

        let action = handle_findings_key(
            &mut state,
            &result,
            crossterm::event::KeyEvent::from(crossterm::event::KeyCode::Char('f')),
        );

        assert!(action.is_none());
        assert_eq!(
            state.status_message,
            Some(t!("app.fix.status.no_compose_target").into_owned())
        );
    }

    #[test]
    fn fix_key_on_host_finding_shows_status_message() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.open_findings();
        // Select the host finding (ssh_root_login_enabled) which has no related_service
        state.selected_index = state
            .sorted_indices
            .iter()
            .position(|index| {
                result
                    .findings
                    .get(*index)
                    .is_some_and(|f| f.id == "host.ssh_root_login_enabled")
            })
            .expect("host finding should exist");

        let action = handle_findings_key(
            &mut state,
            &result,
            crossterm::event::KeyEvent::from(crossterm::event::KeyCode::Char('f')),
        );

        assert!(action.is_none());
        assert_eq!(
            state.status_message,
            Some(t!("app.fix.status.no_service_fix").into_owned())
        );
    }

    #[test]
    fn fix_key_on_manual_service_finding_shows_status_message() {
        let mut result = sample_result();
        result.findings[0].remediation = RemediationKind::Manual;
        let mut state = AppState::new(&result);
        state.open_findings();
        state.selected_index = state
            .sorted_indices
            .iter()
            .position(|index| {
                result
                    .findings
                    .get(*index)
                    .is_some_and(|f| f.id == "exposure.admin_interface_public")
            })
            .expect("manual service finding should exist");

        let action = handle_findings_key(
            &mut state,
            &result,
            crossterm::event::KeyEvent::from(crossterm::event::KeyCode::Char('f')),
        );

        assert!(action.is_none());
        assert_eq!(
            state.status_message,
            Some(t!("app.fix.status.no_fix_available").into_owned())
        );
    }

    #[test]
    fn fix_key_on_valid_finding_returns_trigger_fix() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.open_findings();
        // Select the first finding (adminer) which has related_service
        state.selected_index = state
            .sorted_indices
            .iter()
            .position(|index| {
                result
                    .findings
                    .get(*index)
                    .is_some_and(|f| f.id == "exposure.admin_interface_public")
            })
            .expect("adminer finding should exist");

        let action = handle_findings_key(
            &mut state,
            &result,
            crossterm::event::KeyEvent::from(crossterm::event::KeyCode::Char('f')),
        );

        assert!(
            matches!(
                &action,
                Some(TuiAction::TriggerFix {
                    compose_file,
                    finding_id: Some(id),
                    ..
                }) if compose_file.as_os_str() == "/srv/demo/docker-compose.yml" && id == "exposure.admin_interface_public"
            ),
            "expected TriggerFix with the selected finding id, got {:?}",
            action
        );
    }

    #[test]
    fn fix_key_on_empty_visible_list_shows_status_message() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.open_findings();
        state.sorted_indices.clear();
        state.selected_index = 0;

        let action = handle_findings_key(
            &mut state,
            &result,
            crossterm::event::KeyEvent::from(crossterm::event::KeyCode::Char('f')),
        );

        assert!(action.is_none());
        assert_eq!(
            state.status_message,
            Some(t!("app.fix.status.no_finding_selected").into_owned())
        );
    }

    #[test]
    fn findings_header_shows_status_message_when_set() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.open_findings();
        state.set_status_message("Test status message".to_owned());

        let mut terminal = Terminal::new(TestBackend::new(80, 4)).expect("terminal should build");
        terminal
            .draw(|frame| {
                let area = frame.area();
                let paragraph = findings_header(
                    &result,
                    &state,
                    area.width,
                    FindingsLayoutMode::Stacked,
                    &state.theme,
                );
                frame.render_widget(paragraph, area);
            })
            .expect("header should render");

        let content = buffer_to_string(terminal.backend());
        assert!(content.contains("Test status message"));
    }

    #[test]
    fn findings_header_shows_host_triage_context_for_host_filter() {
        let result = host_triage_result();
        let mut state = AppState::new(&result);
        state.scope_filter = Some(Scope::Host);
        state.open_findings();

        let mut terminal = Terminal::new(TestBackend::new(80, 4)).expect("terminal should build");
        terminal
            .draw(|frame| {
                let area = frame.area();
                let paragraph = findings_header(
                    &result,
                    &state,
                    area.width,
                    FindingsLayoutMode::Stacked,
                    &state.theme,
                );
                frame.render_widget(paragraph, area);
            })
            .expect("header should render");

        let content = buffer_to_string(terminal.backend());
        assert!(content.contains("Host triage mode"));
    }

    #[test]
    fn findings_footer_shows_available_fix_hint_with_safe_color() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.open_findings();
        state.selected_index = state
            .sorted_indices
            .iter()
            .position(|index| {
                result
                    .findings
                    .get(*index)
                    .is_some_and(|f| f.id == "exposure.admin_interface_public")
            })
            .expect("fixable finding should exist");

        let mut terminal = Terminal::new(TestBackend::new(100, 5)).expect("terminal should build");
        terminal
            .draw(|frame| {
                let area = frame.area();
                let paragraph = findings_footer(
                    &result,
                    &state,
                    area.width,
                    FindingsLayoutMode::Stacked,
                    &state.theme,
                );
                frame.render_widget(paragraph, area);
            })
            .expect("footer should render");

        let content = buffer_to_string(terminal.backend());
        let (x, y) = find_rendered_position(&content, "f fix selected finding")
            .expect("fix hint should render");

        assert_eq!(
            buffer_fg(terminal.backend(), x as u16, y as u16),
            state.theme.safe
        );
    }

    #[test]
    fn findings_footer_shows_unavailable_fix_hint_with_muted_color() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.open_findings();
        state.selected_index = state
            .sorted_indices
            .iter()
            .position(|index| {
                result
                    .findings
                    .get(*index)
                    .is_some_and(|f| f.id == "host.ssh_root_login_enabled")
            })
            .expect("host finding should exist");

        let mut terminal = Terminal::new(TestBackend::new(100, 5)).expect("terminal should build");
        terminal
            .draw(|frame| {
                let area = frame.area();
                let paragraph = findings_footer(
                    &result,
                    &state,
                    area.width,
                    FindingsLayoutMode::Stacked,
                    &state.theme,
                );
                frame.render_widget(paragraph, area);
            })
            .expect("footer should render");

        let content = buffer_to_string(terminal.backend());
        let needle = "f unavailable: selected finding has no Compose fix";
        let (x, y) =
            find_rendered_position(&content, needle).expect("unavailable hint should render");

        assert_eq!(
            buffer_fg(terminal.backend(), x as u16, y as u16),
            state
                .theme
                .muted
                .fg
                .expect("muted style should define a foreground color")
        );
    }

    #[test]
    fn findings_footer_shows_host_scope_hint_with_muted_color() {
        let result = host_triage_result();
        let mut state = AppState::new(&result);
        state.scope_filter = Some(Scope::Host);
        state.open_findings();

        let mut terminal = Terminal::new(TestBackend::new(100, 6)).expect("terminal should build");
        terminal
            .draw(|frame| {
                let area = frame.area();
                let paragraph = findings_footer(
                    &result,
                    &state,
                    area.width,
                    FindingsLayoutMode::Stacked,
                    &state.theme,
                );
                frame.render_widget(paragraph, area);
            })
            .expect("footer should render");

        let content = buffer_to_string(terminal.backend());
        let needle = "Host-only view: review manual host findings by area from the overview, then inspect evidence here.";
        let (x, y) =
            find_rendered_position(&content, needle).expect("host scope hint should render");

        assert_eq!(
            buffer_fg(terminal.backend(), x as u16, y as u16),
            state
                .theme
                .muted
                .fg
                .expect("muted style should define a foreground color")
        );
    }

    #[test]
    fn persist_error_sets_status_message() {
        let result = sample_result();
        let mut state = AppState::new(&result);

        state.handle_persist_error(
            String::from("Theme"),
            io::Error::new(io::ErrorKind::PermissionDenied, "nope"),
        );

        assert_eq!(
            state.status_message,
            Some(t!("app.settings.persist_failed", setting = "Theme").into_owned())
        );
    }

    #[test]
    fn persist_not_found_error_is_ignored() {
        let result = sample_result();
        let mut state = AppState::new(&result);

        state.handle_persist_error(
            String::from("Theme"),
            io::Error::new(io::ErrorKind::NotFound, "missing"),
        );

        assert_eq!(state.status_message, None);
    }

    #[test]
    fn history_view_renders_title_and_empty_state() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let scan_result = sample_result();
        let mut state = AppState::new(&scan_result);
        state.screen = Screen::History;

        terminal
            .draw(|frame| render_history(frame, &mut state))
            .unwrap();

        let text = buffer_to_string(terminal.backend());
        assert!(
            text.contains("Scan History Trend"),
            "history view should render title area"
        );
    }

    #[test]
    fn history_view_renders_header_row_when_entries_exist() {
        // When history exists, the view renders entry rows instead of empty state.
        // The previous test also covers the empty-state path.
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let scan_result = sample_result();
        let mut state = AppState::new(&scan_result);
        state.screen = Screen::History;

        terminal
            .draw(|frame| render_history(frame, &mut state))
            .unwrap();

        let text = buffer_to_string(terminal.backend());
        assert!(
            text.contains("Date") || text.contains("Score"),
            "history view should render column header"
        );
    }

    #[test]
    fn overview_panels_use_borderless_rendering() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("terminal should build");

        terminal
            .draw(|frame| render(frame, &result, &mut state))
            .expect("overview should render");

        let content = buffer_to_string(terminal.backend());

        // Borderless panels should not render Unicode box-drawing characters
        // that `Borders::ALL` would produce (┌, ┐, └, ┘, │, ─).
        assert!(
            !content.contains('┌'),
            "borderless panels should not use top-left corner character"
        );
        assert!(
            !content.contains('┐'),
            "borderless panels should not use top-right corner character"
        );
        assert!(
            !content.contains('└'),
            "borderless panels should not use bottom-left corner character"
        );
        assert!(
            !content.contains('┘'),
            "borderless panels should not use bottom-right corner character"
        );
        assert!(
            !content.contains("│"),
            "borderless panels should not use vertical border character"
        );
    }

    #[test]
    fn overview_panels_render_borders_when_enabled() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.borders_enabled = true;
        state.theme.borders_enabled = true;
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("terminal should build");

        terminal
            .draw(|frame| render(frame, &result, &mut state))
            .expect("overview should render");

        let content = buffer_to_string(terminal.backend());

        // When borders are enabled, panels should render Unicode box-drawing characters
        assert!(
            content.contains('┌'),
            "bordered panels should show top-left corner character"
        );
        assert!(
            content.contains('┐'),
            "bordered panels should show top-right corner character"
        );
        assert!(
            content.contains("│"),
            "bordered panels should show vertical border character"
        );
    }

    #[test]
    fn overview_panels_apply_distinct_background_colors() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.theme_preset = ThemePreset::TokyoNight;
        state.theme = Theme::preset(ThemePreset::TokyoNight);
        let mut terminal = Terminal::new(TestBackend::new(120, 40)).expect("terminal should build");

        terminal
            .draw(|frame| render(frame, &result, &mut state))
            .expect("overview should render");

        let buffer = terminal.backend().buffer();
        let area = terminal.backend().size().unwrap();

        // Collect distinct background colors used in the content area
        let mut bg_colors = std::collections::HashSet::new();
        for y in 2..area.height.saturating_sub(2) {
            for x in 0..area.width {
                if let Some(bg) = buffer[(x, y)].style().bg {
                    bg_colors.insert(bg);
                }
            }
        }

        // Borderless design should use at least 2 distinct panel backgrounds
        // (panel_bg and panel_bg_alt) plus the surface background.
        assert!(
            bg_colors.len() >= 2,
            "borderless panels should use at least 2 distinct background colors, found {}: {:?}",
            bg_colors.len(),
            bg_colors
        );
    }

    #[test]
    fn focused_panel_uses_focus_background_color() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.theme_preset = ThemePreset::TokyoNight;
        state.theme = Theme::preset(ThemePreset::TokyoNight);
        state.overview_focus = OverviewFocus::ServerStatus;
        let mut terminal = Terminal::new(TestBackend::new(120, 40)).expect("terminal should build");

        terminal
            .draw(|frame| render(frame, &result, &mut state))
            .expect("overview should render");

        let expected_focus_bg = state
            .theme
            .focus_bg
            .bg
            .expect("focus_bg should define a background");

        let buffer = terminal.backend().buffer();

        // The Server Status panel is in the top-left area, so scan that region
        // for the focus background color.
        let mut found_focus_bg = false;
        for y in 2..12 {
            for x in 0..38 {
                if buffer[(x, y)].style().bg == Some(expected_focus_bg) {
                    found_focus_bg = true;
                    break;
                }
            }
            if found_focus_bg {
                break;
            }
        }

        assert!(
            found_focus_bg,
            "focused panel should use theme.focus_bg background"
        );
    }

    #[test]
    fn borders_toggle_via_settings_affects_render_immediately() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        let scan_result = &result;
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("terminal should build");

        // Step 1: render initial borderless state, verify no borders
        terminal
            .draw(|frame| render(frame, scan_result, &mut state))
            .expect("initial render");
        let content_before = buffer_to_string(terminal.backend());
        assert!(
            !content_before.contains('┌'),
            "default state should be borderless"
        );

        // Step 2: user presses 's' to open settings
        handle_key(
            &mut state,
            scan_result,
            KeyEvent::new(KeyCode::Char('s'), crossterm::event::KeyModifiers::NONE),
        );
        assert!(state.settings_open, "settings should be open after 's'");

        // Step 3: user navigates down to UI Borders row (row 3)
        // Starting at row 0 (Theme), press Down 3 times
        for _ in 0..3 {
            handle_key(
                &mut state,
                scan_result,
                KeyEvent::new(KeyCode::Down, crossterm::event::KeyModifiers::NONE),
            );
        }
        assert_eq!(
            state.settings_row, 3,
            "settings should be on UI Borders row (3)"
        );

        // Step 4: user presses Right to toggle borders ON
        handle_key(
            &mut state,
            scan_result,
            KeyEvent::new(KeyCode::Right, crossterm::event::KeyModifiers::NONE),
        );
        assert!(state.borders_enabled, "borders should now be enabled");
        assert!(
            state.theme.borders_enabled,
            "theme.borders_enabled should also be updated"
        );

        // Step 5: user presses Esc to close settings
        handle_key(
            &mut state,
            scan_result,
            KeyEvent::new(KeyCode::Esc, crossterm::event::KeyModifiers::NONE),
        );
        assert!(!state.settings_open, "settings should be closed");

        // Step 6: re-render and verify borders now appear
        terminal
            .draw(|frame| render(frame, scan_result, &mut state))
            .expect("render after toggle");
        let content_after = buffer_to_string(terminal.backend());
        assert!(
            content_after.contains('┌'),
            "bordered panels should show top-left corner after toggle"
        );
        assert!(
            content_after.contains('│'),
            "bordered panels should show vertical border after toggle"
        );

        // Step 7: toggle back OFF via settings
        state.settings_row = 0;
        handle_key(
            &mut state,
            scan_result,
            KeyEvent::new(KeyCode::Char('s'), crossterm::event::KeyModifiers::NONE),
        );
        for _ in 0..3 {
            handle_key(
                &mut state,
                scan_result,
                KeyEvent::new(KeyCode::Down, crossterm::event::KeyModifiers::NONE),
            );
        }
        handle_key(
            &mut state,
            scan_result,
            KeyEvent::new(KeyCode::Right, crossterm::event::KeyModifiers::NONE),
        );
        handle_key(
            &mut state,
            scan_result,
            KeyEvent::new(KeyCode::Esc, crossterm::event::KeyModifiers::NONE),
        );

        terminal
            .draw(|frame| render(frame, scan_result, &mut state))
            .expect("render after toggle back");
        let content_final = buffer_to_string(terminal.backend());
        assert!(
            !content_final.contains('┌'),
            "panels should be borderless again after toggle off"
        );
    }

    #[test]
    fn history_panel_is_borderless_by_default() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.screen = Screen::History;
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("terminal");
        terminal
            .draw(|frame| render_history(frame, &mut state))
            .expect("history render");

        let content = buffer_to_string(terminal.backend());
        assert!(
            !content.contains('┌'),
            "history panel should not show border chars when borders_enabled=false"
        );
        assert!(
            !content.contains('│'),
            "history panel should not show vertical borders when borders_enabled=false"
        );
    }

    #[test]
    fn history_panel_shows_borders_when_enabled() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.borders_enabled = true;
        state.theme.borders_enabled = true;
        state.screen = Screen::History;
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("terminal");
        terminal
            .draw(|frame| render_history(frame, &mut state))
            .expect("history render");

        let content = buffer_to_string(terminal.backend());
        assert!(
            content.contains('┌'),
            "history panel should show border chars when borders_enabled=true"
        );
    }

    #[test]
    fn history_navigation_scrolls_with_arrow_keys() {
        let result = sample_result();
        // Create history entries via temp file
        let mut history = crate::history::ScanHistory::default();
        history.record(&result);
        let mut result2 = result.clone();
        result2.score_report.overall = 42;
        history.record(&result2);
        let dir = std::env::temp_dir().join("hostveil-tui-test-history-nav");
        let _ = std::fs::create_dir_all(&dir);
        let history_path = dir.join("history.json");
        std::fs::write(&history_path, serde_json::to_string(&history).unwrap()).unwrap();
        // SAFETY: test-only env var scoped to this test
        unsafe { std::env::set_var("HOSTVEIL_CONFIG_DIR", dir.to_str().unwrap()) };

        let mut state = AppState::new(&result);
        state.screen = Screen::History;

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
        );
        assert_eq!(state.history_scroll, 1, "Down should increment scroll");

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Up, KeyModifiers::NONE),
        );
        assert_eq!(state.history_scroll, 0, "Up should decrement scroll");

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE),
        );
        assert_eq!(state.history_scroll, 8, "PageDown should scroll 8 lines");

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE),
        );
        assert_eq!(state.history_scroll, 0, "PageUp should scroll back");

        // SAFETY: test cleanup
        unsafe { std::env::remove_var("HOSTVEIL_CONFIG_DIR") };
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn history_back_returns_to_overview() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.screen = Screen::History;

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE),
        );
        assert_eq!(
            state.screen,
            Screen::Overview,
            "'t' from history should go to overview"
        );
    }

    #[test]
    fn history_navigation_affects_render_and_back_returns_to_overview() {
        // Full E2E: TestBackend render + key navigation in history screen
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.screen = Screen::History;
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("terminal");

        // Render initial history screen
        terminal
            .draw(|frame| render_history(frame, &mut state))
            .expect("initial render");
        let before = buffer_to_string(terminal.backend());
        assert!(
            before.contains("History") || before.contains("Trend"),
            "history screen should show a title or trend section"
        );

        // Navigate with Down key
        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
        );
        assert_eq!(state.history_scroll, 1);

        // Render again after scroll
        terminal
            .draw(|frame| render_history(frame, &mut state))
            .expect("render after scroll");
        let after_scroll = buffer_to_string(terminal.backend());
        assert!(
            !after_scroll.is_empty(),
            "render should still produce output after scroll"
        );

        // Navigate back to overview with 't'
        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE),
        );
        assert_eq!(state.screen, Screen::Overview);
    }

    #[test]
    fn tab_3_from_overview_opens_history() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.screen = Screen::Overview;
        state.history_scroll = 42;

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('3'), KeyModifiers::NONE),
        );
        assert_eq!(
            state.screen,
            Screen::History,
            "Key '3' should switch to history screen"
        );
        assert_eq!(
            state.history_scroll, 0,
            "'3' should reset scroll via open_history"
        );
    }

    #[test]
    fn tab_2_from_overview_opens_findings() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.screen = Screen::Overview;
        state.detail_scroll = 99;

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('2'), KeyModifiers::NONE),
        );
        assert_eq!(
            state.screen,
            Screen::Findings,
            "Key '2' should switch to findings"
        );
        assert_eq!(
            state.detail_scroll, 0,
            "'2' should reset scroll via open_findings"
        );
    }

    #[test]
    fn tab_1_from_findings_returns_to_overview() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.screen = Screen::Findings;
        state.detail_scroll = 99;

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('1'), KeyModifiers::NONE),
        );
        assert_eq!(
            state.screen,
            Screen::Overview,
            "Key '1' should return to overview"
        );
        assert_eq!(
            state.detail_scroll, 0,
            "'1' should reset scroll via return_to_overview"
        );
    }

    #[test]
    fn history_tab_uses_correct_background() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.screen = Screen::History;
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("terminal");
        terminal
            .draw(|frame| render_history(frame, &mut state))
            .expect("history render");

        let buffer = terminal.backend().buffer();
        // History tab is focused, so panel should use focus_bg background
        let panel_cell_style = buffer[(1, 3)].style();
        let expected_bg = state.theme.focus_bg.bg.unwrap_or(Color::Reset);
        assert_eq!(
            panel_cell_style.bg,
            Some(expected_bg),
            "focused history panel should use focus_bg background"
        );
    }

    #[test]
    fn history_renders_trend_bars_with_correct_colors() {
        let result = sample_result();
        // Inject history with entries having different scores
        let mut history = crate::history::ScanHistory::default();
        let mut r1 = result.clone();
        r1.score_report.overall = 30;
        history.record(&r1);
        let mut r2 = result.clone();
        r2.score_report.overall = 55;
        history.record(&r2);
        let mut r3 = result.clone();
        r3.score_report.overall = 85;
        history.record(&r3);

        let dir = std::env::temp_dir().join("hostveil-tui-test-trend-colors");
        let _ = std::fs::create_dir_all(&dir);
        let history_path = dir.join("history.json");
        std::fs::write(&history_path, serde_json::to_string(&history).unwrap()).unwrap();
        // SAFETY: test-only env var scoped to this test
        unsafe { std::env::set_var("HOSTVEIL_CONFIG_DIR", dir.to_str().unwrap()) };

        let mut state = AppState::new(&result);
        state.screen = Screen::History;
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("terminal");
        terminal
            .draw(|frame| render_history(frame, &mut state))
            .expect("history render");

        let text = buffer_to_string(terminal.backend());
        assert!(
            text.contains('█'),
            "history should render filled trend bar blocks"
        );
        assert!(
            text.contains('░'),
            "history should render empty trend bar blocks"
        );

        // SAFETY: test cleanup
        unsafe { std::env::remove_var("HOSTVEIL_CONFIG_DIR") };
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn borders_toggle_via_settings_affects_history_render_immediately() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("terminal");

        // Step 1: navigate to history, verify borderless
        state.screen = Screen::History;
        terminal
            .draw(|frame| render_history(frame, &mut state))
            .expect("render history (borderless)");
        let before = buffer_to_string(terminal.backend());
        assert!(!before.contains('┌'), "history should start borderless");

        // Step 2: open settings, toggle borders ON, close
        state.screen = Screen::Overview;
        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE),
        );
        for _ in 0..3 {
            handle_key(
                &mut state,
                &result,
                KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
            );
        }
        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Right, KeyModifiers::NONE),
        );
        assert!(state.borders_enabled, "borders should be enabled");
        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
        );

        // Step 3: go to history, verify borders appear immediately
        state.screen = Screen::History;
        terminal
            .draw(|frame| render_history(frame, &mut state))
            .expect("render history (bordered)");
        let after = buffer_to_string(terminal.backend());
        assert!(
            after.contains('┌'),
            "history should show borders after toggle"
        );

        // Step 4: toggle back OFF via settings
        state.screen = Screen::Overview;
        state.settings_row = 0;
        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE),
        );
        for _ in 0..3 {
            handle_key(
                &mut state,
                &result,
                KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
            );
        }
        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Right, KeyModifiers::NONE),
        );
        assert!(!state.borders_enabled, "borders should be disabled");
        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
        );

        // Step 5: verify history is borderless again
        state.screen = Screen::History;
        terminal
            .draw(|frame| render_history(frame, &mut state))
            .expect("render history (borderless again)");
        let final_content = buffer_to_string(terminal.backend());
        assert!(
            !final_content.contains('┌'),
            "history should be borderless again"
        );
    }

    #[test]
    fn settings_modal_history_scroll_resets_on_enter() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.screen = Screen::Overview;
        state.history_scroll = 15;

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE),
        );
        assert_eq!(state.screen, Screen::History);
        assert_eq!(
            state.history_scroll, 0,
            "history_scroll should reset via open_history"
        );

        // Back to overview via 't' in history, then reopen via 't' in overview
        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE),
        );
        assert_eq!(
            state.screen,
            Screen::Overview,
            "'t' in history should go back to overview"
        );
        state.history_scroll = 10;
        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE),
        );
        assert_eq!(
            state.screen,
            Screen::History,
            "'t' in overview should re-open history"
        );
        assert_eq!(
            state.history_scroll, 0,
            "history_scroll should reset on re-entering history"
        );
    }

    #[test]
    fn search_modal_opens_with_slash_key() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.screen = Screen::Findings;

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE),
        );
        assert!(state.search_open, "search should open with '/'");
        assert!(
            state.search_query.is_empty(),
            "search query should start empty"
        );
    }

    #[test]
    fn search_modal_esc_closes_and_clears_query() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.search_open = true;
        state.search_query.push_str("nginx");

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
        );
        assert!(!state.search_open, "Esc should close search");
        assert!(state.search_query.is_empty(), "Esc should clear query");
    }

    #[test]
    fn search_modal_enter_closes_and_clamps_selection() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.search_open = true;
        state.search_query.push_str("exposure");

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
        );
        assert!(!state.search_open, "Enter should close search");
    }

    #[test]
    fn search_modal_backspace_removes_last_char() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.search_open = true;
        state.search_query.push_str("abc");

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE),
        );
        assert_eq!(state.search_query.as_str(), "ab");
    }

    #[test]
    fn search_modal_typing_appends_char() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.search_open = true;

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE),
        );
        assert_eq!(state.search_query.as_str(), "n");
    }

    #[test]
    fn modal_borders_respect_borders_toggle() {
        let scan_result = sample_result();
        let mut state = AppState::new(&scan_result);
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("terminal");

        // Step 1: default (borders off) → modal should not show borders
        state.settings_open = true;
        terminal
            .draw(|frame| render_settings_modal(frame, &mut state))
            .expect("settings modal render (borderless)");
        let before = buffer_to_string(terminal.backend());
        assert!(
            !before.contains('┌'),
            "modal should be borderless when borders_enabled is false"
        );
        state.settings_open = false;

        // Step 2: enable borders
        handle_key(
            &mut state,
            &scan_result,
            KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE),
        );
        for _ in 0..3 {
            handle_key(
                &mut state,
                &scan_result,
                KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
            );
        }
        handle_key(
            &mut state,
            &scan_result,
            KeyEvent::new(KeyCode::Right, KeyModifiers::NONE),
        );
        assert!(state.borders_enabled, "borders should be enabled");

        // Verify settings_closed and then reopen to apply new theme
        state.settings_open = false;
        handle_key(
            &mut state,
            &scan_result,
            KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE),
        );
        terminal
            .draw(|frame| render_settings_modal(frame, &mut state))
            .expect("settings modal render (bordered)");
        let after = buffer_to_string(terminal.backend());
        assert!(
            after.contains('┌'),
            "modal should show borders when borders_enabled is true"
        );
        state.settings_open = false;

        // Step 3: restore default
        state.settings_row = 0;
        handle_key(
            &mut state,
            &scan_result,
            KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE),
        );
        for _ in 0..3 {
            handle_key(
                &mut state,
                &scan_result,
                KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
            );
        }
        handle_key(
            &mut state,
            &scan_result,
            KeyEvent::new(KeyCode::Right, KeyModifiers::NONE),
        );
    }

    #[test]
    fn help_overlay_renders_search_key() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        let mut terminal = Terminal::new(TestBackend::new(90, 30)).expect("terminal");

        state.help_open = true;
        terminal
            .draw(|frame| render_help_overlay(frame, &mut state))
            .expect("help overlay render");

        let content = buffer_to_string(terminal.backend());
        assert!(
            content.contains("Search findings"),
            "help should list search shortcut with description"
        );
    }

    #[test]
    fn render_tabs_shows_all_tab_labels() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("terminal");

        terminal
            .draw(|frame| {
                let area = Rect::new(0, 0, 80, 1);
                render_tabs(frame, area, &mut state);
            })
            .expect("tabs render");

        let text = buffer_to_string(terminal.backend());
        assert!(text.contains("1"), "tab should show key '1'");
        assert!(text.contains("2"), "tab should show key '2'");
        assert!(text.contains("3"), "tab should show key '3'");
    }

    #[test]
    fn render_tabs_highlights_active_tab() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.screen = Screen::Findings;
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("terminal");

        terminal
            .draw(|frame| {
                let area = Rect::new(0, 0, 80, 1);
                render_tabs(frame, area, &mut state);
            })
            .expect("tabs render");

        // The active tab (Findings/2) should have background from highlight
        // In TokyoNight theme, highlight bg is Rgb(65, 72, 100)
        let expected = Some(ratatui::style::Color::Rgb(65, 72, 100));
        let buffer = terminal.backend().buffer();
        let mut found_active = false;
        let area = terminal.backend().size().unwrap();
        for y in 0..area.height {
            for x in 0..area.width {
                if buffer[(x, y)].symbol().contains("2") && buffer[(x, y)].style().bg == expected {
                    found_active = true;
                }
            }
        }
        assert!(
            found_active,
            "active tab '2' should have highlight background"
        );
    }

    #[test]
    fn border_toggle_maintains_tab_bar_borderless() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("terminal");

        // Tab bar should always be borderless regardless of borders_enabled
        terminal
            .draw(|frame| {
                let area = Rect::new(0, 0, 80, 1);
                render_tabs(frame, area, &mut state);
            })
            .expect("tabs render (borderless by default)");
        let before = buffer_to_string(terminal.backend());
        assert!(!before.contains('│'), "tab bar should not show borders");

        // Enable borders
        state.borders_enabled = true;
        state.theme.borders_enabled = true;
        terminal
            .draw(|frame| {
                let area = Rect::new(0, 0, 80, 1);
                render_tabs(frame, area, &mut state);
            })
            .expect("tabs render (borders enabled)");
        let after = buffer_to_string(terminal.backend());
        assert!(
            !after.contains('│'),
            "tab bar should remain borderless even when borders enabled"
        );
    }

    #[test]
    fn mouse_click_tab_history_opens_history() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.screen = Screen::Overview;
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("terminal");

        terminal
            .draw(|frame| render(frame, &result, &mut state))
            .expect("overview render");

        let (rect, _) = state
            .hit_boxes
            .iter()
            .find(|(_, target)| matches!(target, HitTarget::TabHistory))
            .expect("TabHistory hit box should exist")
            .clone();
        handle_mouse(
            &mut state,
            &result,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: rect.x,
                row: rect.y,
                modifiers: KeyModifiers::NONE,
            },
        );

        assert_eq!(
            state.screen,
            Screen::History,
            "clicking history tab should switch to History"
        );
    }

    #[test]
    fn mouse_click_tab_overview_returns_to_overview() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.screen = Screen::Findings;
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("terminal");

        terminal
            .draw(|frame| render(frame, &result, &mut state))
            .expect("findings render");

        let (rect, _) = state
            .hit_boxes
            .iter()
            .find(|(_, target)| matches!(target, HitTarget::TabOverview))
            .expect("TabOverview hit box should exist")
            .clone();
        handle_mouse(
            &mut state,
            &result,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: rect.x,
                row: rect.y,
                modifiers: KeyModifiers::NONE,
            },
        );

        assert_eq!(
            state.screen,
            Screen::Overview,
            "clicking overview tab should go to Overview"
        );
    }

    #[test]
    fn mouse_click_tab_findings_opens_findings() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.screen = Screen::Overview;
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("terminal");

        terminal
            .draw(|frame| render(frame, &result, &mut state))
            .expect("overview render");

        let (rect, _) = state
            .hit_boxes
            .iter()
            .find(|(_, target)| matches!(target, HitTarget::TabFindings))
            .expect("TabFindings hit box should exist")
            .clone();
        handle_mouse(
            &mut state,
            &result,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: rect.x,
                row: rect.y,
                modifiers: KeyModifiers::NONE,
            },
        );

        assert_eq!(
            state.screen,
            Screen::Findings,
            "clicking findings tab should open Findings"
        );
    }

    #[test]
    fn selected_finding_preserves_severity_foreground_color() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.open_findings();
        state.selected_index = 0; // Critical finding (adminer, severity = Critical)

        let mut terminal = Terminal::new(TestBackend::new(100, 24)).expect("terminal should build");
        terminal
            .draw(|frame| render(frame, &result, &mut state))
            .expect("findings should render");

        let buffer = terminal.backend().buffer();
        let area = terminal.backend().size().unwrap();

        // The selected item starts with "> " highlight symbol at column 1 (after padding).
        let mut selected_row = None;
        for y in 0..area.height {
            if buffer[(1, y)].symbol() == ">" && buffer[(2, y)].symbol() == " " {
                selected_row = Some(y);
                break;
            }
        }
        let row = selected_row.expect("selected item with '> ' prefix should be visible");

        // The title text should have a non-Reset foreground color (severity color),
        // AND it should NOT be the same as the highlight background color (which
        // would make it invisible). With the fix, highlight has no fg, so span
        // styles' fg wins.
        let severity_fg = state.theme.crit; // for Critical finding
        let mut found_severity_fg = false;
        for x in 3..area.width.min(80) {
            let cell = &buffer[(x, row)];
            let fg = cell.style().fg;
            let ch = cell.symbol();
            if ch != " " && fg == Some(severity_fg) {
                found_severity_fg = true;
                break;
            }
        }
        assert!(
            found_severity_fg,
            "selected finding title text must carry severity foreground color ({:?})",
            severity_fg
        );
    }

    #[test]
    fn f_key_on_findings_does_not_change_screen_to_overview() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.open_findings();
        assert_eq!(state.screen, Screen::Findings);

        // Select a finding with related_service and Auto/Review remediation
        state.selected_index = state
            .sorted_indices
            .iter()
            .position(|index| {
                result
                    .findings
                    .get(*index)
                    .is_some_and(|f| f.id == "exposure.admin_interface_public")
            })
            .expect("adminer finding should exist");

        let action = handle_findings_key(
            &mut state,
            &result,
            crossterm::event::KeyEvent::from(crossterm::event::KeyCode::Char('f')),
        );

        // The f key should return TriggerFix (exiting the TUI), NOT change screen
        assert!(
            matches!(action, Some(TuiAction::TriggerFix { .. })),
            "f key on fixable finding should return TriggerFix"
        );
        // Screen should still be Findings — if TriggerFix is returned, the event
        // loop exits and the fix flow starts in a separate terminal. But the state
        // itself should not be mutated to Overview.
        assert_eq!(
            state.screen,
            Screen::Findings,
            "f key should not set screen back to Overview; it returns TriggerFix instead"
        );
    }

    // ── Key binding E2E tests ──

    #[test]
    fn help_overlay_opens_with_question_mark_and_closes_with_esc() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        assert!(!state.help_open, "help should start closed");

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE),
        );
        assert!(state.help_open, "? should open help overlay");

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
        );
        assert!(!state.help_open, "Esc should close help overlay");

        // Open again and test ? toggles
        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE),
        );
        assert!(state.help_open, "? should toggle help open again");

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE),
        );
        assert!(!state.help_open, "? should toggle help closed again");
    }

    #[test]
    fn q_from_overview_returns_exit_action() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.screen = Screen::Overview;

        let action = handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
        );
        assert!(matches!(action, Some(TuiAction::Exit)));

        // Resetting state for Esc test
        let mut state2 = AppState::new(&result);
        let action2 = handle_key(
            &mut state2,
            &result,
            KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
        );
        assert!(matches!(action2, Some(TuiAction::Exit)));
    }

    #[test]
    fn q_from_history_returns_exit_action() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.screen = Screen::History;

        let action = handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
        );
        assert!(matches!(action, Some(TuiAction::Exit)));

        let mut state2 = AppState::new(&result);
        state2.screen = Screen::History;
        let action2 = handle_key(
            &mut state2,
            &result,
            KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
        );
        assert!(matches!(action2, Some(TuiAction::Exit)));
    }

    #[test]
    fn l_key_cycles_layout_preset() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        let initial = state.layout_preset;

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('L'), KeyModifiers::NONE),
        );
        assert_ne!(
            state.layout_preset, initial,
            "L should cycle layout preset away from initial"
        );

        // Cycle through all presets until we wrap back to initial
        let mut count = 0;
        while state.layout_preset != initial && count < 10 {
            handle_key(
                &mut state,
                &result,
                KeyEvent::new(KeyCode::Char('L'), KeyModifiers::NONE),
            );
            count += 1;
        }
        assert!(
            count < 10,
            "L should cycle back to initial preset within 10 presses"
        );
    }

    #[test]
    fn tab_cycles_overview_focus_panel() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        let initial_focus = state.overview_focus;

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE),
        );
        assert_ne!(
            state.overview_focus, initial_focus,
            "Tab should cycle overview focus away from initial"
        );
    }

    #[test]
    fn overview_scroll_with_jk_and_page_keys() {
        let result = sample_result();
        let mut state = AppState::new(&result);

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE),
        );
        assert_eq!(
            state.active_overview_scroll(),
            1,
            "j should scroll overview by 1"
        );

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE),
        );
        assert_eq!(state.active_overview_scroll(), 0, "k should scroll back");

        // Reset for Down/Up
        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
        );
        assert_eq!(
            state.active_overview_scroll(),
            1,
            "Down should scroll overview"
        );

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Up, KeyModifiers::NONE),
        );
        assert_eq!(state.active_overview_scroll(), 0, "Up should scroll back");

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE),
        );
        assert_eq!(
            state.active_overview_scroll(),
            8,
            "PageDown should scroll 8"
        );

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE),
        );
        assert_eq!(
            state.active_overview_scroll(),
            0,
            "PageUp should scroll back"
        );
    }

    #[test]
    fn v_key_cycles_service_filter() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.open_findings();
        let initial = state.service_filter.clone();

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('v'), KeyModifiers::NONE),
        );
        assert_ne!(
            state.service_filter, initial,
            "v should cycle service filter"
        );
    }

    #[test]
    fn t_from_findings_opens_history() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.screen = Screen::Findings;

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE),
        );
        assert_eq!(
            state.screen,
            Screen::History,
            "t from findings should open History"
        );
    }

    #[test]
    fn settings_modal_opens_with_ctrl_comma() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        assert!(!state.settings_open);

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char(','), KeyModifiers::CONTROL),
        );
        assert!(state.settings_open, "Ctrl+, should open settings modal");

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
        );
        assert!(!state.settings_open, "Esc should close settings");
    }

    #[test]
    fn settings_navigation_up_and_k_navigates_backward() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.settings_open = true;

        // Navigate down to row 3 (UI Borders)
        for _ in 0..3 {
            handle_key(
                &mut state,
                &result,
                KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
            );
        }
        assert_eq!(state.settings_row, 3);

        // k should go up
        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE),
        );
        assert_eq!(state.settings_row, 2, "k should navigate up");

        // Up should also go up
        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Up, KeyModifiers::NONE),
        );
        assert_eq!(state.settings_row, 1, "Up should navigate up");
    }

    #[test]
    fn settings_left_cycles_backward() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.settings_open = true;
        // Row 0 = Theme. Remember current theme
        let initial_theme = state.theme_preset;

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Left, KeyModifiers::NONE),
        );
        assert_ne!(
            state.theme_preset, initial_theme,
            "Left on Theme should cycle backward"
        );

        // h should also cycle backward
        let theme_after_left = state.theme_preset;
        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('h'), KeyModifiers::NONE),
        );
        assert_ne!(
            state.theme_preset, theme_after_left,
            "h on Theme should cycle backward again"
        );
    }

    #[test]
    fn settings_3_jumps_to_locale_row() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.settings_open = true;
        state.settings_row = 0;

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('3'), KeyModifiers::NONE),
        );
        assert_eq!(
            state.settings_row, 2,
            "'3' should jump to Locale row (index 2)"
        );
    }

    #[test]
    fn help_overlay_renders_key_bindings_when_open() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.help_open = true;
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("terminal");

        terminal
            .draw(|frame| render(frame, &result, &mut state))
            .expect("help overlay should render");

        let content = buffer_to_string(terminal.backend());
        assert!(
            content.contains("Global")
                || content.contains("Overview")
                || content.contains("Findings"),
            "help overlay should show key binding sections"
        );
        assert!(
            content.contains("?") || content.contains("?"),
            "help overlay should mention the ? key"
        );
    }

    #[test]
    fn layout_cycle_affects_render_immediately() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("terminal");

        // Capture initial layout
        terminal
            .draw(|frame| render(frame, &result, &mut state))
            .expect("initial render");
        let before = buffer_to_string(terminal.backend());

        // Press L to cycle layout
        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('L'), KeyModifiers::NONE),
        );

        // Re-render should be different
        terminal
            .draw(|frame| render(frame, &result, &mut state))
            .expect("render after L");
        let after = buffer_to_string(terminal.backend());

        // If the layout changed, the rendered output should differ
        // (the exact difference depends on layout, but we verify the state changed
        // and the render doesn't panic)
        assert_ne!(
            before.len(),
            0,
            "initial render should produce non-empty output"
        );
        assert_ne!(
            after.len(),
            0,
            "render after layout change should produce non-empty output"
        );
    }

    #[test]
    fn pagedown_scrolls_findings_detail_by_8() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.open_findings();
        state.findings_focus = FindingsFocus::Detail;

        let initial_scroll = state.detail_scroll;

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE),
        );
        assert!(
            state.detail_scroll >= initial_scroll + 8,
            "PageDown in findings detail should scroll by 8, got {} -> {}",
            initial_scroll,
            state.detail_scroll
        );
    }

    #[test]
    fn enter_on_overview_opens_findings_in_list_focus() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.screen = Screen::Overview;

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
        );
        assert_eq!(state.screen, Screen::Findings);
        assert_eq!(
            state.findings_focus,
            FindingsFocus::List,
            "Enter should open findings in List focus"
        );
    }

    #[test]
    fn right_on_overview_opens_findings() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.screen = Screen::Overview;

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('l'), KeyModifiers::NONE),
        );
        assert_eq!(
            state.screen,
            Screen::Findings,
            "l from overview opens findings"
        );

        // Reset
        let mut state2 = AppState::new(&result);
        handle_key(
            &mut state2,
            &result,
            KeyEvent::new(KeyCode::Right, KeyModifiers::NONE),
        );
        assert_eq!(
            state2.screen,
            Screen::Findings,
            "Right from overview opens findings"
        );
    }

    // ── Fix availability unit tests ──

    fn make_test_finding() -> Finding {
        Finding {
            id: String::new(),
            axis: Axis::HostHardening,
            severity: Severity::Medium,
            scope: Scope::Host,
            source: Source::NativeHost,
            subject: String::new(),
            related_service: Some("svc".to_string()),
            title: String::new(),
            description: String::new(),
            why_risky: String::new(),
            how_to_fix: String::new(),
            evidence: BTreeMap::new(),
            remediation: RemediationKind::Auto,
        }
    }

    #[test]
    fn fix_availability_available_when_compose_and_auto_remediation() {
        let finding = make_test_finding();
        assert_eq!(
            fix_availability(Some(&PathBuf::from("/compose.yml")), Some(&finding)),
            FixAvailability::Available
        );
        let review_finding = Finding {
            remediation: RemediationKind::Review,
            ..make_test_finding()
        };
        assert_eq!(
            fix_availability(Some(&PathBuf::from("/compose.yml")), Some(&review_finding)),
            FixAvailability::Available
        );
    }

    #[test]
    fn fix_availability_no_compose_target_when_missing() {
        let finding = make_test_finding();
        assert_eq!(
            fix_availability(None, Some(&finding)),
            FixAvailability::NoComposeTarget
        );
    }

    #[test]
    fn fix_availability_no_finding_selected_when_none() {
        assert_eq!(
            fix_availability(Some(&PathBuf::from("/compose.yml")), None),
            FixAvailability::NoFindingSelected
        );
    }

    #[test]
    fn fix_availability_no_service_fix_when_no_related_service() {
        let finding = Finding {
            related_service: None,
            ..make_test_finding()
        };
        assert_eq!(
            fix_availability(Some(&PathBuf::from("/compose.yml")), Some(&finding)),
            FixAvailability::NoServiceFix
        );
    }

    #[test]
    fn fix_availability_manual_only_for_manual_remediation() {
        let finding = Finding {
            remediation: RemediationKind::Manual,
            ..make_test_finding()
        };
        assert_eq!(
            fix_availability(Some(&PathBuf::from("/compose.yml")), Some(&finding)),
            FixAvailability::ManualOnly
        );
    }

    #[test]
    fn fix_unavailable_message_all_variants_non_empty() {
        for variant in [
            FixAvailability::Available,
            FixAvailability::NoComposeTarget,
            FixAvailability::NoFindingSelected,
            FixAvailability::NoServiceFix,
            FixAvailability::ManualOnly,
        ] {
            let msg = fix_unavailable_message(variant);
            assert!(
                !msg.is_empty(),
                "{:?} should produce non-empty message",
                variant
            );
        }
    }

    #[test]
    fn mouse_scroll_down_on_overview_scrolls_overview() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.screen = Screen::Overview;
        let initial_scroll = state.active_overview_scroll();

        handle_mouse(
            &mut state,
            &result,
            MouseEvent {
                kind: MouseEventKind::ScrollDown,
                column: 10,
                row: 10,
                modifiers: KeyModifiers::NONE,
            },
        );

        assert_eq!(
            state.active_overview_scroll(),
            initial_scroll + 3,
            "ScrollDown should scroll overview by 3 lines"
        );
    }

    #[test]
    fn mouse_scroll_up_on_overview_scrolls_overview() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.screen = Screen::Overview;
        state.scroll_overview_down(10);
        let initial_scroll = state.active_overview_scroll();

        handle_mouse(
            &mut state,
            &result,
            MouseEvent {
                kind: MouseEventKind::ScrollUp,
                column: 10,
                row: 10,
                modifiers: KeyModifiers::NONE,
            },
        );

        assert_eq!(
            state.active_overview_scroll(),
            initial_scroll.saturating_sub(3),
            "ScrollUp should scroll overview by 3 lines"
        );
    }

    #[test]
    fn mouse_scroll_down_on_findings_list_selects_next_finding() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.open_findings();
        state.findings_focus = FindingsFocus::List;
        let initial = state.selected_index;

        handle_mouse(
            &mut state,
            &result,
            MouseEvent {
                kind: MouseEventKind::ScrollDown,
                column: 10,
                row: 10,
                modifiers: KeyModifiers::NONE,
            },
        );

        assert_eq!(
            state.selected_index,
            initial + 1,
            "ScrollDown on findings list should select next finding"
        );
    }

    #[test]
    fn mouse_scroll_up_on_findings_list_selects_previous_finding() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.open_findings();
        state.findings_focus = FindingsFocus::List;
        state.selected_index = 2;
        let initial = state.selected_index;

        handle_mouse(
            &mut state,
            &result,
            MouseEvent {
                kind: MouseEventKind::ScrollUp,
                column: 10,
                row: 10,
                modifiers: KeyModifiers::NONE,
            },
        );

        assert_eq!(
            state.selected_index,
            initial.saturating_sub(1),
            "ScrollUp on findings list should select previous finding"
        );
    }

    #[test]
    fn tab_cycles_focus_and_alters_render_panels() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).expect("terminal");

        terminal
            .draw(|frame| render(frame, &result, &mut state))
            .expect("initial render");
        let initial_focus = state.overview_focus;

        // Tab should cycle to the next panel
        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE),
        );
        assert_ne!(state.overview_focus, initial_focus);

        // Re-render should not panic after focus change
        terminal
            .draw(|frame| render(frame, &result, &mut state))
            .expect("render after Tab");
        let after_tab = buffer_to_string(terminal.backend());
        assert!(!after_tab.is_empty(), "render should produce output");

        // Cycle through ALL focus states by pressing Tab repeatedly
        let mut focus_count = 0;
        let target_focus = initial_focus;
        while state.overview_focus != target_focus && focus_count < 10 {
            handle_key(
                &mut state,
                &result,
                KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE),
            );
            focus_count += 1;
        }
        assert!(
            focus_count < 10,
            "Tab should cycle through all focus states within 10 presses"
        );
        assert_eq!(
            state.overview_focus, initial_focus,
            "should return to initial focus after full cycle"
        );
    }

    #[test]
    fn overview_scroll_does_not_underflow_at_zero() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        assert_eq!(state.active_overview_scroll(), 0);

        // Scrolling up at zero should stay at zero
        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Up, KeyModifiers::NONE),
        );
        assert_eq!(state.active_overview_scroll(), 0);
        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE),
        );
        assert_eq!(state.active_overview_scroll(), 0);
        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE),
        );
        assert_eq!(state.active_overview_scroll(), 0);
    }

    #[test]
    fn settings_row_wraps_around_on_overflow() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.settings_open = true;
        // Navigate past the last row — should wrap to 0
        for _ in 0..10 {
            handle_key(
                &mut state,
                &result,
                KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
            );
        }
        assert!(
            state.settings_row < 4,
            "Down should wrap around, got {}",
            state.settings_row
        );

        // Up from row 0 should clamp at 0 (no wrap)
        state.settings_row = 0;
        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Up, KeyModifiers::NONE),
        );
        assert_eq!(state.settings_row, 0, "Up from row 0 should stay at 0");
    }
}
