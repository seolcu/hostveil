use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::io;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols;
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, Borders, LineGauge, List, ListItem, ListState, Paragraph, Scrollbar,
    ScrollbarOrientation, ScrollbarState, Wrap,
};

use crate::domain::{
    AdapterStatus, Axis, DefensiveControlStatus, DockerDiscoveryStatus, Finding, HostRuntimeInfo,
    RemediationKind, ScanMode, ScanResult, Scope, Severity, Source,
};
use crate::i18n;

mod fix_review;

pub use fix_review::run_fix_review;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    Overview,
    Findings,
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct AppState {
    screen: Screen,
    findings_focus: FindingsFocus,
    selected_index: usize,
    detail_scroll: u16,
    sorted_indices: Vec<usize>,
    severity_filter: Option<Severity>,
    source_filter: Option<Source>,
    remediation_filter: RemediationFilter,
    sort_mode: FindingSortMode,
}

impl AppState {
    fn new(scan_result: &ScanResult) -> Self {
        let severity_filter = None;
        let source_filter = None;
        let remediation_filter = RemediationFilter::All;
        let sort_mode = FindingSortMode::Severity;

        Self {
            screen: Screen::Overview,
            findings_focus: FindingsFocus::List,
            selected_index: 0,
            detail_scroll: 0,
            sorted_indices: visible_finding_indices(
                scan_result,
                severity_filter,
                source_filter,
                remediation_filter,
                sort_mode,
            ),
            severity_filter,
            source_filter,
            remediation_filter,
            sort_mode,
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
    }

    fn return_to_overview(&mut self) {
        self.screen = Screen::Overview;
        self.findings_focus = FindingsFocus::List;
        self.detail_scroll = 0;
    }

    fn select_next(&mut self) {
        if self.finding_count() > 1 {
            self.selected_index = (self.selected_index + 1).min(self.finding_count() - 1);
            self.detail_scroll = 0;
        }
    }

    fn select_previous(&mut self) {
        if self.finding_count() > 1 {
            self.selected_index = self.selected_index.saturating_sub(1);
            self.detail_scroll = 0;
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
            self.sort_mode,
        );

        if self.sorted_indices.is_empty() {
            self.selected_index = 0;
            self.detail_scroll = 0;
            return;
        }

        self.selected_index = self.selected_index.min(self.sorted_indices.len() - 1);
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
    }

    fn cycle_sort_mode(&mut self) {
        self.sort_mode = match self.sort_mode {
            FindingSortMode::Severity => FindingSortMode::Source,
            FindingSortMode::Source => FindingSortMode::Subject,
            FindingSortMode::Subject => FindingSortMode::Severity,
        };
        self.selected_index = 0;
        self.detail_scroll = 0;
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
    }

    fn reset_filters_and_sort(&mut self) {
        self.severity_filter = None;
        self.source_filter = None;
        self.remediation_filter = RemediationFilter::All;
        self.sort_mode = FindingSortMode::Severity;
        self.selected_index = 0;
        self.detail_scroll = 0;
    }

    fn jump_to_severity(&mut self, scan_result: &ScanResult, severity: Severity) {
        self.clamp_selection(scan_result);

        if let Some(position) = self.sorted_indices.iter().position(|index| {
            scan_result
                .findings
                .get(*index)
                .is_some_and(|finding| finding.severity == severity)
        }) {
            self.selected_index = position;
            self.detail_scroll = 0;
        }
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
    Compact,
    Narrow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FindingsLayoutMode {
    SideBySide,
    Stacked,
    Narrow,
}

pub enum TuiAction {
    Exit,
    TriggerFix(std::path::PathBuf),
}

pub fn run<F>(scan_result: &mut ScanResult, mut refresh: F) -> io::Result<TuiAction>
where
    F: FnMut(&mut ScanResult) -> bool,
{
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let mut state = AppState::new(scan_result);

    let result = run_event_loop(&mut terminal, scan_result, &mut state, &mut refresh);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
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

        terminal.draw(|frame| render(frame, scan_result, state))?;

        if event::poll(Duration::from_millis(100))? {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    if let Some(action) = handle_key(state, scan_result, key) {
                        return Ok(action);
                    }
                }
                Event::Resize(_, _) => {}
                _ => {}
            }
        }
    }
}

fn handle_key(state: &mut AppState, scan_result: &ScanResult, key: KeyEvent) -> Option<TuiAction> {
    match state.screen {
        Screen::Overview => handle_overview_key(state, scan_result, key),
        Screen::Findings => handle_findings_key(state, scan_result, key),
    }
}

fn handle_overview_key(
    state: &mut AppState,
    scan_result: &ScanResult,
    key: KeyEvent,
) -> Option<TuiAction> {
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => Some(TuiAction::Exit),
        KeyCode::Char('g') => {
            let _ = i18n::cycle_persisted_locale();
            None
        }
        KeyCode::Char('f') => scan_result
            .metadata
            .compose_file
            .clone()
            .map(TuiAction::TriggerFix),
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
        KeyCode::Char('s') => {
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
        KeyCode::Char('o') => {
            state.cycle_sort_mode();
            None
        }
        KeyCode::Char('r') => {
            state.reset_filters_and_sort();
            None
        }
        KeyCode::Char('g') => {
            let _ = i18n::cycle_persisted_locale();
            None
        }
        KeyCode::Char('f') => scan_result
            .metadata
            .compose_file
            .clone()
            .map(TuiAction::TriggerFix),
        KeyCode::Char('1') => {
            state.jump_to_severity(scan_result, Severity::Critical);
            None
        }
        KeyCode::Char('2') => {
            state.jump_to_severity(scan_result, Severity::High);
            None
        }
        KeyCode::Char('3') => {
            state.jump_to_severity(scan_result, Severity::Medium);
            None
        }
        KeyCode::Char('4') => {
            state.jump_to_severity(scan_result, Severity::Low);
            None
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
    state.clamp_selection(scan_result);

    match state.screen {
        Screen::Overview => render_overview(frame, scan_result),
        Screen::Findings => render_findings(frame, scan_result, state),
    }
}

fn render_overview(frame: &mut ratatui::Frame<'_>, scan_result: &ScanResult) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(12),
            Constraint::Length(2),
        ])
        .split(frame.area());

    frame.render_widget(header_banner(), layout[0]);

    match overview_layout_mode(frame.area()) {
        OverviewLayoutMode::Wide => {
            let dashboard = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(layout[1]);

            let top_row = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(dashboard[0]);

            let bottom_row = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(dashboard[1]);

            render_server_status_panel(frame, top_row[0], scan_result);
            render_scan_results_panel(frame, top_row[1], scan_result);
            render_security_scores_panel(frame, bottom_row[0], scan_result);
            render_fix_paths_panel(frame, bottom_row[1], scan_result);
        }
        OverviewLayoutMode::Compact => {
            let rows = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Percentage(34),
                    Constraint::Percentage(33),
                    Constraint::Percentage(33),
                ])
                .split(layout[1]);
            let top_row = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(rows[0]);

            render_server_status_panel(frame, top_row[0], scan_result);
            render_scan_results_panel(frame, top_row[1], scan_result);
            render_security_scores_panel(frame, rows[1], scan_result);
            render_fix_paths_panel(frame, rows[2], scan_result);
        }
        OverviewLayoutMode::Narrow => {
            let rows = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Percentage(27),
                    Constraint::Percentage(25),
                    Constraint::Percentage(24),
                    Constraint::Percentage(24),
                ])
                .split(layout[1]);

            render_server_status_panel(frame, rows[0], scan_result);
            render_scan_results_panel(frame, rows[1], scan_result);
            render_security_scores_panel(frame, rows[2], scan_result);
            render_fix_paths_panel(frame, rows[3], scan_result);
        }
    }

    frame.render_widget(overview_footer(), layout[2]);
}

fn render_findings(frame: &mut ratatui::Frame<'_>, scan_result: &ScanResult, state: &mut AppState) {
    let mode = findings_layout_mode(frame.area());
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(frame.area());

    let content = match mode {
        FindingsLayoutMode::SideBySide => Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(layout[1]),
        FindingsLayoutMode::Stacked => Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
            .split(layout[1]),
        FindingsLayoutMode::Narrow => Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
            .split(layout[1]),
    };

    frame.render_widget(
        findings_header(scan_result, state, layout[0].width, mode),
        layout[0],
    );

    let mut list_state = ListState::default();
    if state.finding_count() > 0 {
        list_state.select(Some(state.selected_index));
    }

    let list = List::new(findings_list_items(
        scan_result,
        state,
        content[0].width,
        mode,
    ))
    .block(
        Block::default()
            .title(findings_list_title(state.findings_focus))
            .borders(Borders::ALL)
            .border_style(focus_border_style(
                state.findings_focus == FindingsFocus::List,
            )),
    )
    .highlight_symbol("> ")
    .highlight_style(Style::default().bg(Color::DarkGray));

    let detail_block = Block::default()
        .title(findings_detail_title(state.findings_focus))
        .borders(Borders::ALL)
        .border_style(focus_border_style(
            state.findings_focus == FindingsFocus::Detail,
        ));
    let detail_inner = detail_block.inner(content[1]);
    let detail_text = finding_detail_text(scan_result, state, detail_inner.width, mode);
    let detail_content_height = estimated_wrapped_text_height(&detail_text, detail_inner.width);
    let detail_max_scroll = detail_content_height.saturating_sub(detail_inner.height as usize);
    state.clamp_detail_scroll(detail_max_scroll);

    let detail = Paragraph::new(detail_text)
        .block(detail_block)
        .wrap(Wrap { trim: true })
        .scroll((state.detail_scroll, 0));

    frame.render_stateful_widget(list, content[0], &mut list_state);
    frame.render_widget(detail, content[1]);
    render_detail_scrollbar(
        frame,
        content[1],
        detail_content_height,
        detail_inner.height,
        state,
    );
    frame.render_widget(
        findings_footer(state.findings_focus, layout[2].width, mode),
        layout[2],
    );
}

fn overview_layout_mode(area: Rect) -> OverviewLayoutMode {
    if area.width >= 110 && area.height >= 28 {
        OverviewLayoutMode::Wide
    } else if area.width >= 80 && area.height >= 24 {
        OverviewLayoutMode::Compact
    } else {
        OverviewLayoutMode::Narrow
    }
}

fn findings_layout_mode(area: Rect) -> FindingsLayoutMode {
    if area.width >= 96 && area.height >= 24 {
        FindingsLayoutMode::SideBySide
    } else if area.width >= 72 && area.height >= 18 {
        FindingsLayoutMode::Stacked
    } else {
        FindingsLayoutMode::Narrow
    }
}

fn header_banner() -> Paragraph<'static> {
    Paragraph::new(Text::from(Line::from(vec![
        Span::styled(
            format!("hostveil v{}", env!("CARGO_PKG_VERSION")),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" | "),
        Span::styled(
            t!("app.header.subtitle").into_owned(),
            Style::default().fg(Color::White),
        ),
        Span::raw(" | "),
        Span::styled(
            current_locale_badge(),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
    ])))
    .alignment(Alignment::Center)
    .block(Block::default().borders(Borders::TOP | Borders::BOTTOM))
}

fn render_server_status_panel(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    scan_result: &ScanResult,
) {
    let block = Block::default()
        .title(t!("app.panel.server_status").into_owned())
        .borders(Borders::ALL)
        .border_style(panel_border_style());
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Length(1),
            Constraint::Min(0),
        ])
        .split(inner);

    let meta_lines = vec![
        kv_line(
            t!("app.server.host_name").into_owned(),
            display_hostname(scan_result),
        ),
        kv_line(
            t!("app.server.root_path").into_owned(),
            display_host_root(scan_result),
        ),
        kv_line(
            t!("app.server.docker_version").into_owned(),
            display_docker_version(scan_result),
        ),
        kv_line(
            t!("app.server.uptime").into_owned(),
            display_uptime(scan_result),
        ),
    ];

    frame.render_widget(
        Paragraph::new(Text::from(meta_lines)).wrap(Wrap { trim: true }),
        sections[0],
    );
    render_load_gauge_row(frame, sections[1], scan_result);
    frame.render_widget(
        Paragraph::new(Text::from(server_service_lines(
            scan_result,
            sections[2].width,
        )))
        .wrap(Wrap { trim: true }),
        sections[2],
    );
}

fn render_scan_results_panel(frame: &mut ratatui::Frame<'_>, area: Rect, scan_result: &ScanResult) {
    let block = Block::default()
        .title(t!("app.panel.scan_results").into_owned())
        .borders(Borders::ALL)
        .border_style(panel_border_style());
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let mut lines = result_summary_lines(scan_result, inner.width);
    lines.push(Line::raw(String::new()));
    lines.extend(severity_total_lines(scan_result, inner.width));

    if let Some(docker_status) = &scan_result.metadata.docker_status {
        lines.push(Line::raw(String::new()));
        lines.push(Line::styled(
            t!("app.result.discovery_heading").into_owned(),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
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

    let adapter_lines = adapter_summary_lines(scan_result, inner.width);
    if !adapter_lines.is_empty() {
        lines.push(Line::raw(String::new()));
        lines.extend(adapter_lines);
    }

    if !scan_result.metadata.warnings.is_empty() {
        lines.push(Line::raw(String::new()));
        lines.push(Line::styled(
            t!("app.result.warnings_heading").into_owned(),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ));
        for warning in scan_result.metadata.warnings.iter().take(2) {
            let warning_width = inner.width.saturating_sub(4).max(20) as usize;
            lines.push(Line::raw(format!(
                "- {}",
                truncate_text(warning, warning_width)
            )));
        }
    }

    frame.render_widget(
        Paragraph::new(Text::from(lines)).wrap(Wrap { trim: true }),
        inner,
    );
}

fn render_security_scores_panel(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    scan_result: &ScanResult,
) {
    let block = Block::default()
        .title(t!("app.panel.security_scores").into_owned())
        .borders(Borders::ALL)
        .border_style(panel_border_style());
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let rows = score_rows(scan_result);
    let constraints = rows
        .iter()
        .map(|_| Constraint::Length(1))
        .collect::<Vec<_>>();
    let row_areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner);

    for ((label, score, emphasize), row_area) in rows.into_iter().zip(row_areas.iter().copied()) {
        render_score_gauge_row(frame, row_area, &label, score, emphasize);
    }
}

fn render_fix_paths_panel(frame: &mut ratatui::Frame<'_>, area: Rect, scan_result: &ScanResult) {
    let block = Block::default()
        .title(t!("app.panel.remediation_summary").into_owned())
        .borders(Borders::ALL)
        .border_style(panel_border_style());
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let mut lines = remediation_lines(scan_result, inner.width);
    if lines.is_empty() {
        lines.push(Line::raw(t!("app.fix.none").into_owned()));
    }

    frame.render_widget(
        Paragraph::new(Text::from(lines)).wrap(Wrap { trim: true }),
        inner,
    );
}

fn overview_footer() -> Paragraph<'static> {
    Paragraph::new(Text::from(Line::from(vec![
        hint_span("q", t!("app.footer.quit").into_owned()),
        Span::raw("  "),
        hint_span("Enter", t!("app.footer.findings").into_owned()),
        Span::raw("  "),
        hint_span("g", t!("app.footer.locale").into_owned()),
        Span::raw("  "),
        hint_span("--json", t!("app.footer.json").into_owned()),
    ])))
    .alignment(Alignment::Left)
    .block(Block::default().borders(Borders::TOP))
}

fn findings_header(
    scan_result: &ScanResult,
    state: &AppState,
    available_width: u16,
    mode: FindingsLayoutMode,
) -> Paragraph<'static> {
    let inner_width = available_width.saturating_sub(2).max(16) as usize;
    let filters = finding_filter_summary(state);
    let text = if state.finding_count() == 0 {
        truncate_text(
            &format!(
                "{} | {}",
                t!("app.finding.empty_status").into_owned(),
                filters
            ),
            inner_width,
        )
    } else if mode == FindingsLayoutMode::SideBySide {
        let selection = t!(
            "app.finding.status",
            index = state.selected_index + 1,
            count = state.finding_count(),
            focus = focus_label(state.findings_focus)
        )
        .into_owned();
        let scan_status = compose_status(scan_result);
        truncate_text(
            &format!("{} | {} | {}", selection, filters, scan_status),
            inner_width,
        )
    } else {
        truncate_text(
            &format!(
                "{}/{} | {} | {}",
                state.selected_index + 1,
                state.finding_count(),
                focus_label(state.findings_focus),
                filters,
            ),
            inner_width,
        )
    };

    Paragraph::new(text)
        .block(
            Block::default()
                .title(t!("app.panel.status").into_owned())
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: true })
}

fn findings_footer(
    focus: FindingsFocus,
    available_width: u16,
    mode: FindingsLayoutMode,
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
        Line::raw(truncate_text(&movement, inner_width)),
        Line::raw(truncate_text(&controls, inner_width)),
    ]))
    .block(Block::default().borders(Borders::TOP))
    .wrap(Wrap { trim: true })
}

fn findings_list_items(
    scan_result: &ScanResult,
    state: &AppState,
    available_width: u16,
    mode: FindingsLayoutMode,
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
            let title = truncate_text(
                &format!(
                    "[{}][{}] {}",
                    severity_short_label(finding.severity),
                    remediation_badge,
                    finding.title
                ),
                inner_width,
            );

            match mode {
                FindingsLayoutMode::Narrow => ListItem::new(Line::styled(
                    truncate_text(
                        &format!(
                            "[{}][{}] {} - {}",
                            severity_short_label(finding.severity),
                            remediation_compact,
                            finding.title,
                            compact_subject
                        ),
                        inner_width,
                    ),
                    severity_style(finding.severity).add_modifier(Modifier::BOLD),
                )),
                FindingsLayoutMode::Stacked => ListItem::new(Text::from(vec![
                    Line::styled(
                        title,
                        severity_style(finding.severity).add_modifier(Modifier::BOLD),
                    ),
                    Line::raw(truncate_text(
                        &format!(
                            "{} | {} | {}",
                            source_label(finding.source),
                            compact_subject,
                            remediation_badge
                        ),
                        inner_width,
                    )),
                ])),
                FindingsLayoutMode::SideBySide => ListItem::new(Text::from(vec![
                    Line::styled(
                        title,
                        severity_style(finding.severity).add_modifier(Modifier::BOLD),
                    ),
                    Line::raw(truncate_text(
                        &format!(
                            "{} | {} | {} | {}",
                            source_label(finding.source),
                            scope_label(finding.scope),
                            finding.subject,
                            remediation_badge
                        ),
                        inner_width,
                    )),
                ])),
            }
        })
        .collect()
}

fn finding_detail_text(
    scan_result: &ScanResult,
    state: &AppState,
    available_width: u16,
    mode: FindingsLayoutMode,
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
            severity_style(finding.severity).add_modifier(Modifier::BOLD),
        ),
        Line::raw(if compact {
            truncate_text(
                &format!(
                    "{} | {} | {} | {}",
                    severity_label(finding.severity),
                    source_label(finding.source),
                    finding_list_subject(finding),
                    remediation_badge_text(finding.remediation)
                ),
                available_width.max(16) as usize,
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

fn result_summary_lines(scan_result: &ScanResult, available_width: u16) -> Vec<Line<'static>> {
    let rows = result_summary_rows(scan_result);
    if rows.is_empty() {
        return vec![Line::raw(t!("app.result.none").into_owned())];
    }

    let label_width = available_width.saturating_sub(20).clamp(8, 16) as usize;

    rows.into_iter()
        .map(|row| {
            let status_text = match row.severity {
                Some(severity) => severity_label(severity),
                None => t!("app.result.ok").into_owned(),
            };
            let status_style = match row.severity {
                Some(severity) => severity_style(severity),
                None => Style::default().fg(Color::Green),
            };
            let label = truncate_text(&row.label, label_width);

            Line::from(vec![
                Span::styled("* ", Style::default().fg(Color::Green)),
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

fn severity_total_lines(scan_result: &ScanResult, available_width: u16) -> Vec<Line<'static>> {
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
            severity_style(Severity::Critical).add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            format!("{high} {}", t!("severity.high").into_owned()),
            severity_style(Severity::High).add_modifier(Modifier::BOLD),
        ),
    ]);
    let second_pair = Line::from(vec![
        Span::styled(
            format!("{medium} {}", t!("severity.medium").into_owned()),
            severity_style(Severity::Medium).add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            format!("{low} {}", t!("severity.low").into_owned()),
            severity_style(Severity::Low).add_modifier(Modifier::BOLD),
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
                    severity_style(Severity::Critical).add_modifier(Modifier::BOLD),
                ),
                Span::raw("  "),
                Span::styled(
                    format!("{high} {}", t!("severity.high").into_owned()),
                    severity_style(Severity::High).add_modifier(Modifier::BOLD),
                ),
                Span::raw("  "),
                Span::styled(
                    format!("{medium} {}", t!("severity.medium").into_owned()),
                    severity_style(Severity::Medium).add_modifier(Modifier::BOLD),
                ),
                Span::raw("  "),
                Span::styled(
                    format!("{low} {}", t!("severity.low").into_owned()),
                    severity_style(Severity::Low).add_modifier(Modifier::BOLD),
                ),
            ]),
        ]
    }
}

fn remediation_lines(scan_result: &ScanResult, _available_width: u16) -> Vec<Line<'static>> {
    let auto_fixable_count = scan_result
        .findings
        .iter()
        .filter(|f| {
            matches!(
                f.remediation,
                crate::domain::RemediationKind::Safe | crate::domain::RemediationKind::Guided
            )
        })
        .count();

    let manual_count = scan_result.findings.len() - auto_fixable_count;

    let mut lines = Vec::new();

    if auto_fixable_count > 0 {
        lines.push(Line::from(vec![
            Span::styled(
                format!("[{}] ", t!("remediation.auto_fixable").into_owned()),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(
                t!(
                    "app.result.auto_fixable_summary",
                    count = auto_fixable_count
                )
                .into_owned(),
            ),
        ]));
    }

    if manual_count > 0 {
        lines.push(Line::from(vec![
            Span::styled(
                format!("[{}] ", t!("remediation.manual").into_owned()),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(t!("app.result.manual_summary", count = manual_count).into_owned()),
        ]));
    }

    if auto_fixable_count == 0 && manual_count == 0 {
        lines.push(Line::raw(
            t!("app.result.no_remediation_needed").into_owned(),
        ));
    } else if auto_fixable_count > 0 {
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            t!("app.hint.press_f_to_fix").into_owned(),
            Style::default().fg(Color::Green),
        ));
    }

    lines
}

fn server_service_lines(scan_result: &ScanResult, available_width: u16) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    lines.extend(defensive_controls_lines(scan_result, available_width));

    lines.push(Line::styled(
        t!("app.server.services_heading").into_owned(),
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
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
        let summary = truncate_text(&format!("{} - {}", service.name, image), text_width);
        lines.push(Line::from(vec![
            Span::styled("* ", Style::default().fg(Color::Green)),
            Span::raw(summary),
        ]));
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

fn defensive_controls_lines(scan_result: &ScanResult, available_width: u16) -> Vec<Line<'static>> {
    let Some(runtime) = scan_result.metadata.host_runtime.as_ref() else {
        return Vec::new();
    };
    let text_width = available_width.saturating_sub(4).max(20) as usize;
    let fail2ban = defensive_control_summary(
        t!("app.server.fail2ban").into_owned(),
        runtime.fail2ban,
        fail2ban_detail(runtime),
    );
    vec![Line::raw(truncate_text(
        &format!("{}: {}", t!("app.server.controls").into_owned(), fail2ban),
        text_width,
    ))]
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

fn render_score_gauge_row(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    label: &str,
    score: u8,
    emphasize: bool,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }

    let label_width = area.width.saturating_sub(14).clamp(8, 18);
    let row = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(label_width),
            Constraint::Length(4),
            Constraint::Min(0),
        ])
        .split(area);

    let label_style = if emphasize {
        Style::default().add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    let label_text = truncate_text(label, label_width.saturating_sub(1).max(4) as usize);

    frame.render_widget(Paragraph::new(label_text).style(label_style), row[0]);
    frame.render_widget(
        Paragraph::new(format!("{score:>3}"))
            .style(score_style(score).add_modifier(Modifier::BOLD)),
        row[1],
    );

    if row[2].width > 0 {
        frame.render_widget(
            LineGauge::default()
                .ratio(score_ratio(score))
                .label(String::new())
                .line_set(symbols::line::THICK)
                .filled_style(score_style(score))
                .unfilled_style(Style::default().fg(Color::DarkGray)),
            row[2],
        );
    }
}

fn render_load_gauge_row(frame: &mut ratatui::Frame<'_>, area: Rect, scan_result: &ScanResult) {
    if area.width == 0 || area.height == 0 {
        return;
    }

    let label_text = format!(
        "{} {}",
        t!("app.server.load").into_owned(),
        load_display(scan_result)
    );
    let label_width = area.width.saturating_sub(12).clamp(10, 24);
    let row = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(label_width), Constraint::Min(0)])
        .split(area);

    frame.render_widget(
        Paragraph::new(truncate_text(
            &label_text,
            label_width.saturating_sub(1).max(6) as usize,
        ))
        .style(Style::default().fg(Color::Cyan)),
        row[0],
    );

    if row[1].width > 0 {
        frame.render_widget(
            LineGauge::default()
                .ratio(load_ratio(scan_result).unwrap_or(0.0))
                .label(String::new())
                .line_set(symbols::line::THICK)
                .filled_style(Style::default().fg(Color::Green))
                .unfilled_style(Style::default().fg(Color::DarkGray)),
            row[1],
        );
    }
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

fn score_ratio(score: u8) -> f64 {
    (score as f64 / 100.0).clamp(0.0, 1.0)
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
    sort_mode: FindingSortMode,
) -> Vec<usize> {
    let mut indices = (0..scan_result.findings.len()).collect::<Vec<_>>();
    indices.retain(|index| {
        scan_result.findings.get(*index).is_some_and(|finding| {
            severity_filter.is_none_or(|severity| finding.severity == severity)
                && source_filter.is_none_or(|source| finding.source == source)
                && remediation_filter_matches(finding.remediation, remediation_filter)
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
        "{}:{} {}:{} {}:{} {}:{}",
        t!("app.finding.severity_filter_short").into_owned(),
        severity_filter_label(state.severity_filter),
        t!("app.finding.source_filter_short").into_owned(),
        source_filter_label(state.source_filter),
        t!("app.finding.remediation_filter_short").into_owned(),
        remediation_filter_label(state.remediation_filter),
        t!("app.finding.sort_short").into_owned(),
        sort_mode_label(state.sort_mode),
    )
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

fn compose_status(scan_result: &ScanResult) -> String {
    if scan_result.metadata.scan_mode == ScanMode::Live {
        return match &scan_result.metadata.docker_status {
            Some(DockerDiscoveryStatus::Available)
                if !scan_result.metadata.discovered_projects.is_empty() =>
            {
                t!(
                    "app.status.live_discovery",
                    project_count = scan_result.metadata.discovered_projects.len()
                )
                .into_owned()
            }
            Some(DockerDiscoveryStatus::Missing) => {
                t!("app.status.live_docker_missing").into_owned()
            }
            Some(DockerDiscoveryStatus::PermissionDenied) => {
                t!("app.status.live_docker_denied").into_owned()
            }
            Some(DockerDiscoveryStatus::Failed(_)) => {
                t!("app.status.live_docker_failed").into_owned()
            }
            _ => t!("app.status.live_host_only").into_owned(),
        };
    }

    match (
        &scan_result.metadata.compose_file,
        &scan_result.metadata.host_root,
    ) {
        (Some(path), Some(_)) => i18n::tr_status_compose_and_host_loaded(
            &path.display().to_string(),
            scan_result.metadata.service_count,
        ),
        (Some(path), None) => i18n::tr_status_compose_loaded(
            &path.display().to_string(),
            scan_result.metadata.service_count,
        ),
        (None, Some(path)) => i18n::tr_status_host_loaded(&path.display().to_string()),
        (None, None) => i18n::tr("app.status.no_target"),
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

fn adapter_summary_lines(scan_result: &ScanResult, available_width: u16) -> Vec<Line<'static>> {
    if scan_result.metadata.adapters.is_empty() {
        return Vec::new();
    }

    let text_width = available_width.saturating_sub(4).max(20) as usize;
    let mut lines = vec![Line::styled(
        t!("app.result.adapters_heading").into_owned(),
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )];

    for (name, status) in &scan_result.metadata.adapters {
        lines.push(Line::raw(truncate_text(
            &format!(
                "* {}: {}",
                adapter_name_label(name),
                adapter_status_label(status)
            ),
            text_width,
        )));
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
        AdapterStatus::Pending => t!("adapter.pending").into_owned(),
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

fn load_ratio(scan_result: &ScanResult) -> Option<f64> {
    let runtime = scan_result.metadata.host_runtime.as_ref()?;
    let first = runtime
        .load_average
        .as_deref()?
        .split_whitespace()
        .next()?
        .parse::<f64>()
        .ok()?;

    Some((first / 2.0).clamp(0.0, 1.0))
}

fn defensive_control_status_label(status: DefensiveControlStatus) -> String {
    match status {
        DefensiveControlStatus::NotDetected => t!("app.server.control_not_detected").into_owned(),
        DefensiveControlStatus::Installed => t!("app.server.control_installed").into_owned(),
        DefensiveControlStatus::Enabled => t!("app.server.control_enabled").into_owned(),
    }
}

fn kv_line(label: String, value: String) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label: <14}"), Style::default().fg(Color::Cyan)),
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

fn panel_border_style() -> Style {
    Style::default().fg(Color::Cyan)
}

fn focus_border_style(active: bool) -> Style {
    if active {
        Style::default().fg(Color::Green)
    } else {
        panel_border_style()
    }
}

fn hint_span(key: &str, label: String) -> Span<'static> {
    Span::styled(format!("[{key}] {label}"), Style::default().fg(Color::Cyan))
}

fn truncate_text(value: &str, max_chars: usize) -> String {
    let count = value.chars().count();
    if count <= max_chars {
        return value.to_owned();
    }

    value
        .chars()
        .take(max_chars.saturating_sub(3))
        .collect::<String>()
        + "..."
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

fn severity_style(severity: Severity) -> Style {
    Style::default().fg(match severity {
        Severity::Critical => Color::Red,
        Severity::High => Color::LightRed,
        Severity::Medium => Color::Yellow,
        Severity::Low => Color::Green,
    })
}

fn score_style(score: u8) -> Style {
    Style::default().fg(if score >= 80 {
        Color::Green
    } else if score >= 60 {
        Color::Yellow
    } else {
        Color::LightRed
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use ratatui::Terminal;
    use ratatui::backend::{Backend, TestBackend};

    use super::*;
    use crate::domain::{
        AdapterStatus, DiscoveredProjectSummary, DockerDiscoveryStatus, HostRuntimeInfo,
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
            KeyEvent::new(KeyCode::Char('s'), crossterm::event::KeyModifiers::NONE),
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
    fn findings_controls_can_jump_to_requested_severity() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.open_findings();

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('4'), crossterm::event::KeyModifiers::NONE),
        );
        assert_eq!(
            state
                .selected_finding(&result)
                .map(|finding| finding.severity),
            Some(Severity::Low)
        );

        handle_key(
            &mut state,
            &result,
            KeyEvent::new(KeyCode::Char('1'), crossterm::event::KeyModifiers::NONE),
        );
        assert_eq!(
            state
                .selected_finding(&result)
                .map(|finding| finding.severity),
            Some(Severity::Critical)
        );
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
        assert!(content.contains("Remediation Summary"));
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
        let lines = remediation_lines(&sample_result(), 80);

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
        assert!(content.contains("Fail2ban enabled (2 jails, 5 banned)"));
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
        assert!(content.contains("Remediation Summary"));
        assert!(content.contains("0.42 0.31 0.27"));
        assert!(!content.contains("########"));
        assert!(!content.contains("----------"));
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
        assert!(content.contains("s sev | x src | m rem | o sort | r reset"));
        assert!(!content.contains("PageUp/PageDown"));
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
}
