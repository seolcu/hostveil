use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::io;
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
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, Borders, Clear, List, ListItem, ListState, Paragraph, Scrollbar, ScrollbarOrientation,
    ScrollbarState, Wrap,
};

use crate::domain::{
    AdapterStatus, Axis, DefensiveControlStatus, DockerDiscoveryStatus, Finding, HostRuntimeInfo,
    RemediationKind, ScanResult, Scope, Severity, Source,
};
use crate::i18n;
use crate::settings;

mod fix_review;
mod theme;

pub use fix_review::run_fix_review;
pub use theme::{Theme, ThemePreset};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    Overview,
    Findings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum LayoutPreset {
    Adaptive,
    Wide,
    Balanced,
    Compact,
    Focus,
}

impl LayoutPreset {
    fn as_key(self) -> &'static str {
        match self {
            Self::Adaptive => "adaptive",
            Self::Wide => "wide",
            Self::Balanced => "balanced",
            Self::Compact => "compact",
            Self::Focus => "focus",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Adaptive => "Auto",
            Self::Wide => "Wide",
            Self::Balanced => "Balanced",
            Self::Compact => "Compact",
            Self::Focus => "Focus",
        }
    }

    fn from_key(value: &str) -> Option<Self> {
        match value {
            "adaptive" => Some(Self::Adaptive),
            "wide" => Some(Self::Wide),
            "balanced" => Some(Self::Balanced),
            "compact" => Some(Self::Compact),
            "focus" => Some(Self::Focus),
            _ => None,
        }
    }

    fn next(self) -> Self {
        match self {
            Self::Adaptive => Self::Wide,
            Self::Wide => Self::Balanced,
            Self::Balanced => Self::Compact,
            Self::Compact => Self::Focus,
            Self::Focus => Self::Adaptive,
        }
    }

    fn previous(self) -> Self {
        match self {
            Self::Adaptive => Self::Focus,
            Self::Wide => Self::Adaptive,
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
}

impl SettingsRow {
    fn all() -> [Self; 3] {
        [Self::Theme, Self::Layout, Self::Locale]
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
    Safe,
    Guided,
    Manual,
}

#[derive(Debug, Clone)]
enum HitTarget {
    TabOverview,
    TabFindings,
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
    settings_row: usize,
    findings_focus: FindingsFocus,
    overview_focus: OverviewFocus,
    selected_index: usize,
    detail_scroll: u16,
    findings_list_scroll: u16,
    overview_scroll: BTreeMap<OverviewFocus, u16>,
    sorted_indices: Vec<usize>,
    severity_filter: Option<Severity>,
    source_filter: Option<Source>,
    remediation_filter: RemediationFilter,
    service_filter: Option<String>,
    sort_mode: FindingSortMode,
    layout_preset: LayoutPreset,
    theme: Theme,
    theme_preset: ThemePreset,
    tick: usize,
}

impl AppState {
    fn cycle_theme(&mut self) {
        self.theme_preset = self.theme_preset.next();
        self.theme = Theme::preset(self.theme_preset);
        persist_theme_choice(self.theme_preset.as_key());
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

        Self {
            hit_boxes: Vec::new(),
            screen: Screen::Overview,
            settings_open: false,
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
            sorted_indices: visible_finding_indices(
                scan_result,
                severity_filter,
                source_filter,
                remediation_filter,
                service_filter.as_deref(),
                sort_mode,
            ),
            severity_filter,
            source_filter,
            remediation_filter,
            service_filter: None,
            sort_mode,
            layout_preset,
            theme: Theme::preset(theme_preset),
            theme_preset,
            tick: 0,
        }
    }

    fn cycle_layout(&mut self) {
        self.layout_preset = self.layout_preset.next();
        persist_layout_choice(self.layout_preset.as_key());
    }

    fn cycle_layout_backward(&mut self) {
        self.layout_preset = self.layout_preset.previous();
        persist_layout_choice(self.layout_preset.as_key());
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
                let _ = i18n::cycle_persisted_locale();
            }
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
                let _ = i18n::cycle_persisted_locale();
            }
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
            self.remediation_filter,
            self.service_filter.as_deref(),
            self.sort_mode,
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
            Some(Source::Dockle) => None,
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
            RemediationFilter::Fixable => RemediationFilter::Safe,
            RemediationFilter::Safe => RemediationFilter::Guided,
            RemediationFilter::Guided => RemediationFilter::Manual,
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
            _ => None,
        }
    }

    fn parse_remediation_filter(value: &str) -> Option<RemediationFilter> {
        match value {
            "all" => Some(RemediationFilter::All),
            "fixable" => Some(RemediationFilter::Fixable),
            "safe" => Some(RemediationFilter::Safe),
            "guided" => Some(RemediationFilter::Guided),
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

    fn persist_findings_view(&self) {
        #[cfg(not(test))]
        let _ = settings::persist_findings_view(
            self.severity_filter.map(|s| s.as_key()),
            self.source_filter.map(|s| s.as_key()),
            self.service_filter.as_deref(),
            Some(match self.remediation_filter {
                RemediationFilter::All => "all",
                RemediationFilter::Fixable => "fixable",
                RemediationFilter::Safe => "safe",
                RemediationFilter::Guided => "guided",
                RemediationFilter::Manual => "manual",
            }),
            Some(match self.sort_mode {
                FindingSortMode::Severity => "severity",
                FindingSortMode::Source => "source",
                FindingSortMode::Subject => "subject",
            }),
        );
    }
}

fn persist_theme_choice(theme: &str) {
    #[cfg(not(test))]
    let _ = settings::persist_theme(theme);
    #[cfg(test)]
    let _ = theme;
}

fn persist_layout_choice(layout: &str) {
    #[cfg(not(test))]
    let _ = settings::persist_layout(layout);
    #[cfg(test)]
    let _ = layout;
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

pub enum TuiAction {
    Exit,
    TriggerFix {
        compose_file: std::path::PathBuf,
        finding_id: Option<String>,
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
                    state.scroll_detail_down(2);
                }
            } else {
                state.scroll_overview_down(2);
            }
        }
        MouseEventKind::ScrollUp => {
            if state.settings_open {
                state.settings_prev_row();
            } else if state.screen == Screen::Findings {
                if state.findings_focus == FindingsFocus::List {
                    state.select_previous();
                } else {
                    state.scroll_detail_up(2);
                }
            } else {
                state.scroll_overview_up(2);
            }
        }
        _ => {}
    }

    state.clamp_selection(scan_result);
}

fn handle_key(state: &mut AppState, scan_result: &ScanResult, key: KeyEvent) -> Option<TuiAction> {
    if state.settings_open {
        return handle_settings_key(state, key);
    }

    if matches!(key.code, KeyCode::Char('?'))
        || (matches!(key.code, KeyCode::Char(',')) && key.modifiers.contains(KeyModifiers::CONTROL))
    {
        state.open_settings();
        return None;
    }

    match key.code {
        KeyCode::Char('1') => {
            state.screen = Screen::Overview;
            return None;
        }
        KeyCode::Char('2') => {
            state.screen = Screen::Findings;
            return None;
        }
        KeyCode::Char('s') => {
            state.open_settings();
            return None;
        }
        _ => {}
    }

    match state.screen {
        Screen::Overview => handle_overview_key(state, scan_result, key),
        Screen::Findings => handle_findings_key(state, scan_result, key),
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
        KeyCode::Esc | KeyCode::Enter => {
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

fn handle_overview_key(
    state: &mut AppState,
    scan_result: &ScanResult,
    key: KeyEvent,
) -> Option<TuiAction> {
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => Some(TuiAction::Exit),
        KeyCode::Char('f') => {
            scan_result
                .metadata
                .compose_file
                .clone()
                .map(|path| TuiAction::TriggerFix {
                    compose_file: path,
                    finding_id: None,
                })
        }
        KeyCode::Char('L') => {
            state.cycle_layout();
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
        KeyCode::Char('r') => {
            state.reset_filters_and_sort();
            None
        }
        KeyCode::Char('f') => {
            scan_result
                .metadata
                .compose_file
                .clone()
                .map(|path| TuiAction::TriggerFix {
                    compose_file: path,
                    finding_id: state
                        .selected_finding(scan_result)
                        .map(|finding| finding.id.clone()),
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

fn render(frame: &mut ratatui::Frame<'_>, scan_result: &ScanResult, state: &mut AppState) {
    state.hit_boxes.clear();
    state.clamp_selection(scan_result);
    render_surface_background(frame, &state.theme);

    match state.screen {
        Screen::Overview => render_overview(frame, scan_result, state),
        Screen::Findings => render_findings(frame, scan_result, state),
    }

    if state.settings_open {
        render_settings_modal(frame, state);
    }
}

fn render_surface_background(frame: &mut ratatui::Frame<'_>, theme: &Theme) {
    frame.render_widget(Block::default().style(theme.surface), frame.area());
}

fn render_overview(frame: &mut ratatui::Frame<'_>, scan_result: &ScanResult, state: &mut AppState) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Min(12),
            Constraint::Length(2),
        ])
        .split(frame.area());

    header_banner(frame, state, layout[0]);

    match overview_layout_mode(frame.area(), state.layout_preset) {
        OverviewLayoutMode::Wide => {
            let columns = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Percentage(31),
                    Constraint::Percentage(33),
                    Constraint::Percentage(36),
                ])
                .split(layout[1]);
            let right_column = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(10), Constraint::Min(10)])
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

            render_server_status_panel(frame, columns[0], scan_result, state, &state.theme, state.overview_focus == OverviewFocus::ServerStatus);
            render_scan_results_panel(frame, columns[1], scan_result, state, &state.theme, state.overview_focus == OverviewFocus::ScanResults);
            render_security_scores_panel(frame, right_column[0], scan_result, state, &state.theme, state.overview_focus == OverviewFocus::SecurityScores);
            render_fix_paths_panel(frame, right_column[1], scan_result, state, &state.theme, state.overview_focus == OverviewFocus::FixPaths);
        }
        OverviewLayoutMode::Tall => {
            let rows = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Percentage(20),
                    Constraint::Percentage(30),
                    Constraint::Percentage(20),
                    Constraint::Percentage(30),
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

            render_server_status_panel(frame, rows[0], scan_result, state, &state.theme, state.overview_focus == OverviewFocus::ServerStatus);
            render_scan_results_panel(frame, rows[1], scan_result, state, &state.theme, state.overview_focus == OverviewFocus::ScanResults);
            render_security_scores_panel(frame, rows[2], scan_result, state, &state.theme, state.overview_focus == OverviewFocus::SecurityScores);
            render_fix_paths_panel(frame, rows[3], scan_result, state, &state.theme, state.overview_focus == OverviewFocus::FixPaths);
        }
        OverviewLayoutMode::Compact => {
            let columns = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(layout[1]);
            let left = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(48), Constraint::Percentage(52)])
                .split(columns[0]);
            let right = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(10), Constraint::Min(9)])
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

            render_server_status_panel(frame, left[0], scan_result, state, &state.theme, state.overview_focus == OverviewFocus::ServerStatus);
            render_scan_results_panel(frame, left[1], scan_result, state, &state.theme, state.overview_focus == OverviewFocus::ScanResults);
            render_security_scores_panel(frame, right[0], scan_result, state, &state.theme, state.overview_focus == OverviewFocus::SecurityScores);
            render_fix_paths_panel(frame, right[1], scan_result, state, &state.theme, state.overview_focus == OverviewFocus::FixPaths);
        }
        OverviewLayoutMode::Narrow => {
            let rows = Layout::default()
                .direction(Direction::Vertical)
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

            render_server_status_panel(frame, rows[0], scan_result, state, &state.theme, state.overview_focus == OverviewFocus::ServerStatus);
            render_scan_results_panel(frame, rows[1], scan_result, state, &state.theme, state.overview_focus == OverviewFocus::ScanResults);
            render_security_scores_panel(frame, rows[2], scan_result, state, &state.theme, state.overview_focus == OverviewFocus::SecurityScores);
            render_fix_paths_panel(frame, rows[3], scan_result, state, &state.theme, state.overview_focus == OverviewFocus::FixPaths);
        }
        OverviewLayoutMode::Focus => {
            let columns = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(48), Constraint::Percentage(52)])
                .split(layout[1]);
            render_security_scores_panel(frame, columns[0], scan_result, state, &state.theme, state.overview_focus == OverviewFocus::SecurityScores);
            render_scan_results_panel(frame, columns[1], scan_result, state, &state.theme, state.overview_focus == OverviewFocus::ScanResults);
        }
    }

    frame.render_widget(overview_footer(&state.theme), layout[2]);
}

fn render_findings(frame: &mut ratatui::Frame<'_>, scan_result: &ScanResult, state: &mut AppState) {
    let mode = findings_layout_mode(frame.area(), state.layout_preset);
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(frame.area());

    header_banner(frame, state, layout[0]);

    let content = match mode {
        FindingsLayoutMode::SideBySide => Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(44), Constraint::Percentage(56)])
            .split(layout[1]),
        FindingsLayoutMode::Stacked => Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
            .split(layout[1]),
        FindingsLayoutMode::Narrow => Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
            .split(layout[1]),
        FindingsLayoutMode::CompactList => Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(layout[1]),
    };

    frame.render_widget(
        findings_header(scan_result, state, layout[0].width, mode, &state.theme),
        layout[0],
    );

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

    let list = List::new(visible_items)
        .style(state.theme.surface)
        .block(
            Block::default()
                .title(findings_list_title(state.findings_focus))
                .borders(Borders::ALL)
                .style(state.theme.surface)
                .border_style(focus_border_style(
                    state.findings_focus == FindingsFocus::List,
                    &state.theme,
                )),
        )
        .highlight_symbol("> ")
        .highlight_style(state.theme.highlight);

    let detail_block = Block::default()
        .title(findings_detail_title(state.findings_focus))
        .borders(Borders::ALL)
        .style(state.theme.surface)
        .border_style(focus_border_style(
            state.findings_focus == FindingsFocus::Detail,
            &state.theme,
        ));
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
        findings_footer(state.findings_focus, layout[2].width, mode, &state.theme),
        layout[2],
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
        LayoutPreset::Adaptive => {
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
        LayoutPreset::Adaptive => {
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

fn header_banner(frame: &mut ratatui::Frame<'_>, state: &mut AppState, area: Rect) {
    let theme = &state.theme;
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(3)])
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
    let constraints = [Constraint::Min(20), Constraint::Min(20), Constraint::Min(1)];
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(constraints)
        .split(area);

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
    ];

    for (i, (screen, target, label, key)) in tabs.iter().enumerate() {
        let is_active = state.screen == *screen;
        let style = if is_active {
            theme
                .title
                .add_modifier(Modifier::BOLD)
                .bg(theme.highlight.fg.unwrap_or(ratatui::style::Color::Reset))
        } else {
            theme.base
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(if is_active { theme.title } else { theme.border });

        state.hit_boxes.push((chunks[i], target.clone()));

        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(format!("[{}] ", key), theme.muted),
                Span::styled(label.clone(), style),
            ]))
            .alignment(Alignment::Center)
            .block(block),
            chunks[i],
        );
    }
}

fn render_settings_modal(frame: &mut ratatui::Frame<'_>, state: &mut AppState) {
    let area = frame.area();
    let modal = centered_rect(70, 50, area);
    let modal = clamp_rect_width(modal, 80);

    let theme = &state.theme;

    // Dim the background behind the modal
    frame.render_widget(
        Block::default().style(theme.surface.add_modifier(Modifier::DIM)),
        area,
    );
    frame.render_widget(Clear, modal);
    let block = Block::default()
        .title(format!(" {} ", t!("app.panel.settings")))
        .borders(Borders::ALL)
        .border_style(theme.title)
        .style(theme.surface);
    let inner = block.inner(modal);
    frame.render_widget(block, modal);

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header/Tabs
            Constraint::Min(1),    // Settings
            Constraint::Length(1), // Footer
        ])
        .split(inner);

    let categories = [
        t!("app.settings.category_appearance").into_owned(),
        t!("app.settings.category_localization").into_owned(),
    ];
    let cat_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(layout[0]);

    for (i, cat) in categories.iter().enumerate() {
        frame.render_widget(
            Paragraph::new(cat.to_string())
                .alignment(Alignment::Center)
                .block(
                    Block::default()
                        .borders(Borders::BOTTOM)
                        .border_style(if i == 0 { theme.title } else { theme.border }),
                ),
            cat_layout[i],
        );
    }

    let current_locale = i18n::current_locale();
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
    let block = Block::default()
        .title(t!("app.panel.server_status").into_owned())
        .borders(Borders::ALL)
        .border_style(if is_focused { theme.title } else { theme.border })
        .title_style(theme.title)
        .style(theme.surface);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.width == 0 || inner.height == 0 {
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
    lines.extend(server_service_lines(scan_result, inner.width, theme));

    let content = Text::from(lines);
    let content_height = estimated_wrapped_text_height(&content, inner.width);
    let max_scroll = content_height.saturating_sub(inner.height as usize);
    let scroll = state
        .overview_scroll
        .get(&OverviewFocus::ServerStatus)
        .copied()
        .unwrap_or(0)
        .min(max_scroll.min(u16::MAX as usize) as u16);

    frame.render_widget(
        Paragraph::new(content)
            .style(theme.surface)
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0)),
        inner,
    );
    render_scrollbar(frame, area, content_height, inner.height, scroll);
}

fn render_scan_results_panel(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    scan_result: &ScanResult,
    state: &AppState,
    theme: &Theme,
    is_focused: bool,
) {
    let block = Block::default()
        .title(t!("app.panel.scan_results").into_owned())
        .borders(Borders::ALL)
        .border_style(if is_focused { theme.title } else { theme.border })
        .title_style(theme.title)
        .style(theme.surface);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let mut lines = result_summary_lines(scan_result, inner.width, theme);
    lines.push(Line::raw(String::new()));
    lines.extend(severity_total_lines(scan_result, inner.width, theme));
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

    let adapter_lines = adapter_summary_lines(scan_result, inner.width, state, theme);
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
            let warning_width = inner.width.saturating_sub(4).max(20) as usize;
            for wrapped in wrap_text_to_lines(warning, warning_width) {
                lines.push(Line::raw(format!("- {}", wrapped)));
            }
        }
    }

    let content = Text::from(lines);
    let content_height = estimated_wrapped_text_height(&content, inner.width);
    let max_scroll = content_height.saturating_sub(inner.height as usize);
    let scroll = state
        .overview_scroll
        .get(&OverviewFocus::ScanResults)
        .copied()
        .unwrap_or(0)
        .min(max_scroll.min(u16::MAX as usize) as u16);

    frame.render_widget(
        Paragraph::new(content)
            .style(theme.surface)
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0)),
        inner,
    );
    render_scrollbar(frame, area, content_height, inner.height, scroll);
}

fn render_security_scores_panel(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    scan_result: &ScanResult,
    state: &AppState,
    theme: &Theme,
    is_focused: bool,
) {
    let block = Block::default()
        .title(t!("app.panel.security_scores").into_owned())
        .borders(Borders::ALL)
        .border_style(if is_focused { theme.title } else { theme.border })
        .title_style(theme.title)
        .style(theme.surface);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let text_width = inner.width.saturating_sub(2).max(16) as usize;
    let mut lines = Vec::new();
    if has_pending_adapters(scan_result) {
        lines.push(Line::raw(
            wrap_text_to_lines(&adapter_progress_label(scan_result, state.tick), text_width)
                .join(" "),
        ));
        lines.push(Line::raw(
            t!("app.overview.score_pending_detail").into_owned(),
        ));
        lines.push(Line::raw(String::new()));
    }
    for (label, score, _) in score_rows(scan_result) {
        lines.push(Line::raw(format!("{}: {}", label, score)));
    }

    let content = Text::from(lines);
    let content_height = estimated_wrapped_text_height(&content, inner.width);
    let max_scroll = content_height.saturating_sub(inner.height as usize);
    let scroll = state
        .overview_scroll
        .get(&OverviewFocus::SecurityScores)
        .copied()
        .unwrap_or(0)
        .min(max_scroll.min(u16::MAX as usize) as u16);

    frame.render_widget(
        Paragraph::new(content)
            .style(theme.surface)
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0)),
        inner,
    );
    render_scrollbar(frame, area, content_height, inner.height, scroll);
}

fn render_fix_paths_panel(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    scan_result: &ScanResult,
    state: &AppState,
    theme: &Theme,
    is_focused: bool,
) {
    let block = Block::default()
        .title(t!("app.panel.action_queue"))
        .borders(Borders::ALL)
        .border_style(if is_focused { theme.title } else { theme.border })
        .title_style(theme.title)
        .style(theme.surface);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let mut lines = remediation_lines(scan_result, inner.width, theme);
    if lines.is_empty() {
        lines.push(Line::raw(t!("app.fix.none").into_owned()));
    }

    let content = Text::from(lines);
    let content_height = estimated_wrapped_text_height(&content, inner.width);
    let max_scroll = content_height.saturating_sub(inner.height as usize);
    let scroll = state
        .overview_scroll
        .get(&OverviewFocus::FixPaths)
        .copied()
        .unwrap_or(0)
        .min(max_scroll.min(u16::MAX as usize) as u16);

    frame.render_widget(
        Paragraph::new(content)
            .style(theme.surface)
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0)),
        inner,
    );
    render_scrollbar(frame, area, content_height, inner.height, scroll);
}

fn overview_footer(theme: &Theme) -> Paragraph<'static> {
    Paragraph::new(Text::from(Line::from(vec![
        hint_span("q", t!("app.footer.quit").into_owned(), theme),
        Span::raw("  "),
        hint_span("Enter", t!("app.footer.findings").into_owned(), theme),
        Span::raw("  "),
        hint_span("s", t!("app.footer.settings").into_owned(), theme),
        Span::raw("  "),
        hint_span("--json", t!("app.footer.json").into_owned(), theme),
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

fn findings_header(
    _scan_result: &ScanResult,
    state: &AppState,
    available_width: u16,
    mode: FindingsLayoutMode,
    theme: &Theme,
) -> Paragraph<'static> {
    let inner_width = available_width.saturating_sub(2).max(16) as usize;
    let filters = finding_filter_summary(state);
    let text = if state.finding_count() == 0 {
        let tabs = format!(
            "[1] {} | [2] {} | [3] {}",
            t!("app.tab.overview").into_owned(),
            t!("app.tab.findings").into_owned(),
            t!("app.tab.settings").into_owned()
        );
        format!(
            "{} | {} | {}",
            t!("app.finding.empty_status").into_owned(),
            tabs,
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

    Paragraph::new(Text::from(vec![Line::raw(
        wrap_text_to_lines(&text, inner_width).join(" "),
    )]))
    .block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(theme.border)
            .title(t!("app.panel.findings_header").into_owned())
            .title_style(theme.title),
    )
    .style(theme.surface)
    .wrap(Wrap { trim: true })
}

fn findings_footer(
    focus: FindingsFocus,
    available_width: u16,
    mode: FindingsLayoutMode,
    theme: &Theme,
) -> Paragraph<'static> {
    let inner_width = available_width.saturating_sub(2).max(16) as usize;
    let movement = match focus {
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

    Paragraph::new(Text::from(vec![
        Line::raw(wrap_text_to_lines(&movement, inner_width).join(" ")),
        Line::raw(wrap_text_to_lines(&controls, inner_width).join(" ")),
    ]))
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
            for (i, line) in title_lines.iter().enumerate() {
                if i == 0 {
                    lines.push(Line::styled(line.clone(), style));
                } else {
                    lines.push(Line::raw(format!("  {}", line)));
                }
            }

            match mode {
                FindingsLayoutMode::Narrow => {
                    let subtitle = format!("[{}] {}", remediation_compact, compact_subject);
                    lines.push(Line::raw(format!("  {}", subtitle)));
                }
                FindingsLayoutMode::Stacked => {
                    let subtitle = format!(
                        "{} | {} | {}",
                        source_label(finding.source),
                        compact_subject,
                        remediation_badge
                    );
                    for sub_line in wrap_text_to_lines(&subtitle, inner_width) {
                        lines.push(Line::raw(format!("  {}", sub_line)));
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
                        lines.push(Line::raw(format!("  {}", sub_line)));
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
    let mut host_manual_count = 0;

    for finding in &scan_result.findings {
        match finding.remediation {
            crate::domain::RemediationKind::Safe | crate::domain::RemediationKind::Guided => {
                if let Some(service) = &finding.related_service {
                    *fixable_by_service.entry(service.clone()).or_default() += 1;
                }
            }
            crate::domain::RemediationKind::None => {
                if let Some(service) = &finding.related_service {
                    *manual_by_service.entry(service.clone()).or_default() += 1;
                } else {
                    host_manual_count += 1;
                }
            }
        }
    }

    let auto_fixable_count: usize = fixable_by_service.values().sum();
    let manual_count: usize = manual_by_service.values().sum::<usize>() + host_manual_count;

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
                remediation_style(RemediationKind::Safe, theme).add_modifier(Modifier::BOLD),
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
                remediation_style(RemediationKind::None, theme).add_modifier(Modifier::BOLD),
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

        if host_manual_count > 0 {
            lines.push(Line::from(vec![
                Span::raw("  • "),
                Span::styled(
                    t!("scope.host").into_owned(),
                    theme.base.add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!(": {}", host_manual_count)),
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

    if auto_fixable_count > 0 {
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

fn visible_finding_indices(
    scan_result: &ScanResult,
    severity_filter: Option<Severity>,
    source_filter: Option<Source>,
    remediation_filter: RemediationFilter,
    service_filter: Option<&str>,
    sort_mode: FindingSortMode,
) -> Vec<usize> {
    let mut indices = (0..scan_result.findings.len()).collect::<Vec<_>>();
    indices.retain(|index| {
        scan_result.findings.get(*index).is_some_and(|finding| {
            severity_filter.is_none_or(|severity| finding.severity == severity)
                && source_filter.is_none_or(|source| finding.source == source)
                && remediation_filter_matches(finding.remediation, remediation_filter)
                && service_filter
                    .is_none_or(|service| finding.related_service.as_deref() == Some(service))
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
        RemediationFilter::Fixable => remediation != RemediationKind::None,
        RemediationFilter::Safe => remediation == RemediationKind::Safe,
        RemediationFilter::Guided => remediation == RemediationKind::Guided,
        RemediationFilter::Manual => remediation == RemediationKind::None,
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
        RemediationFilter::Safe => t!("app.finding.filter_safe").into_owned(),
        RemediationFilter::Guided => t!("app.finding.filter_guided").into_owned(),
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

fn focus_border_style(active: bool, theme: &Theme) -> Style {
    if active { theme.title } else { theme.border }
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
        RemediationKind::Safe => t!("app.finding.remediation_badge.safe").into_owned(),
        RemediationKind::Guided => t!("app.finding.remediation_badge.guided").into_owned(),
        RemediationKind::None => t!("app.finding.remediation_badge.manual").into_owned(),
    }
}

fn remediation_badge_compact(remediation: RemediationKind) -> String {
    match remediation {
        RemediationKind::Safe => t!("app.finding.remediation_badge_compact.safe").into_owned(),
        RemediationKind::Guided => t!("app.finding.remediation_badge_compact.guided").into_owned(),
        RemediationKind::None => t!("app.finding.remediation_badge_compact.manual").into_owned(),
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
        RemediationKind::Safe => theme.safe,
        RemediationKind::Guided => theme.guided,
        RemediationKind::None => theme.manual,
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
                    remediation: RemediationKind::Guided,
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
                    remediation: RemediationKind::None,
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
                    remediation: RemediationKind::Safe,
                },
            ],
            score_report: ScoreReport {
                overall: 61,
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
            remediation: RemediationKind::None,
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
            remediation: RemediationKind::None,
        });
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
        assert_eq!(state.remediation_filter, RemediationFilter::Safe);
        assert_eq!(state.finding_count(), 1);

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('m'), crossterm::event::KeyModifiers::NONE),
        );
        state.clamp_selection(&result);
        assert_eq!(state.remediation_filter, RemediationFilter::Guided);
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
    fn overview_renders_full_metadata_in_wide_layout() {
        let result = sample_result();
        let mut state = AppState::new(&result);
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
        // Footer now intentionally shares the surface background for visual consistency.
        assert_eq!(themed_footer_bg, themed_body_bg);

        let mut ansi_state = AppState::new(&result);
        ansi_state.theme_preset = ThemePreset::Ansi;
        ansi_state.theme = Theme::preset(ThemePreset::Ansi);
        let mut ansi_terminal =
            Terminal::new(TestBackend::new(80, 24)).expect("terminal should build");

        ansi_terminal
            .draw(|frame| render(frame, &result, &mut ansi_state))
            .expect("ansi overview should render");

        assert_eq!(
            buffer_bg(ansi_terminal.backend(), 10, 10),
            ratatui::style::Color::Reset
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
        assert!(content.contains("[GUIDED]"));
        assert!(content.contains("Admin interface is exposed publicly"));
        assert!(content.contains("Native Compose | Service | adminer | GUIDED"));
        assert!(content.contains("rem:all"));
        assert!(content.contains("adminer"));
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
        let mut terminal = Terminal::new(TestBackend::new(60, 20)).expect("terminal should build");

        terminal
            .draw(|frame| render(frame, &result, &mut state))
            .expect("narrow findings view should render");

        let content = buffer_to_string(terminal.backend());

        assert!(content.contains("[CRIT][G] Admin interface is exposed publicly - adminer"));
        assert!(content.contains("Critical | Native Compose | adminer | GUIDED"));
        assert!(content.contains("S sev | x src | v svc | m rem | o sort"));
        assert!(!content.contains("PageUp/PageDown"));
    }

    #[test]
    fn tui_buffers_do_not_use_visible_ellipsis_for_security_content() {
        let result = long_content_result();
        let mut overview_state = AppState::new(&result);
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
        assert!(content.contains("Appearance"));
        assert!(content.contains("Localization"));

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
}
