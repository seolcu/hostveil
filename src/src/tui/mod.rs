use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::io;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};

use crate::domain::{
    Axis, DockerDiscoveryStatus, Finding, RemediationKind, ScanMode, ScanResult, Scope, Severity,
    Source,
};
use crate::i18n;

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

#[derive(Debug, Clone, PartialEq, Eq)]
struct AppState {
    screen: Screen,
    findings_focus: FindingsFocus,
    selected_index: usize,
    detail_scroll: u16,
    sorted_indices: Vec<usize>,
}

impl AppState {
    fn new(scan_result: &ScanResult) -> Self {
        Self {
            screen: Screen::Overview,
            findings_focus: FindingsFocus::List,
            selected_index: 0,
            detail_scroll: 0,
            sorted_indices: sorted_finding_indices(scan_result),
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResultSummaryRow {
    label: String,
    severity: Option<Severity>,
    count: usize,
}

pub fn run(scan_result: &ScanResult) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let mut state = AppState::new(scan_result);

    let result = run_event_loop(&mut terminal, scan_result, &mut state);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    scan_result: &ScanResult,
    state: &mut AppState,
) -> io::Result<()> {
    loop {
        terminal.draw(|frame| render(frame, scan_result, state))?;

        if let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
            && handle_key(state, key)
        {
            return Ok(());
        }
    }
}

fn handle_key(state: &mut AppState, key: KeyEvent) -> bool {
    match state.screen {
        Screen::Overview => handle_overview_key(state, key),
        Screen::Findings => handle_findings_key(state, key),
    }
}

fn handle_overview_key(state: &mut AppState, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => true,
        KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
            state.open_findings();
            false
        }
        _ => false,
    }
}

fn handle_findings_key(state: &mut AppState, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => {
            state.return_to_overview();
            false
        }
        KeyCode::Tab => {
            state.toggle_focus();
            false
        }
        KeyCode::Left | KeyCode::Char('h') => {
            state.focus_list();
            false
        }
        KeyCode::Right | KeyCode::Char('l') | KeyCode::Enter => {
            state.focus_detail();
            false
        }
        KeyCode::Down | KeyCode::Char('j') => {
            match state.findings_focus {
                FindingsFocus::List => state.select_next(),
                FindingsFocus::Detail => state.scroll_detail_down(1),
            }
            false
        }
        KeyCode::Up | KeyCode::Char('k') => {
            match state.findings_focus {
                FindingsFocus::List => state.select_previous(),
                FindingsFocus::Detail => state.scroll_detail_up(1),
            }
            false
        }
        KeyCode::PageDown => {
            state.scroll_detail_down(8);
            false
        }
        KeyCode::PageUp => {
            state.scroll_detail_up(8);
            false
        }
        _ => false,
    }
}

fn render(frame: &mut ratatui::Frame<'_>, scan_result: &ScanResult, state: &AppState) {
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

    frame.render_widget(header_banner(), layout[0]);
    render_server_status_panel(frame, top_row[0], scan_result);
    render_scan_results_panel(frame, top_row[1], scan_result);
    render_security_scores_panel(frame, bottom_row[0], scan_result);
    render_fix_paths_panel(frame, bottom_row[1], scan_result);
    frame.render_widget(overview_footer(), layout[2]);
}

fn render_findings(frame: &mut ratatui::Frame<'_>, scan_result: &ScanResult, state: &AppState) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(frame.area());

    let content = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(layout[1]);

    frame.render_widget(findings_header(scan_result, state), layout[0]);

    let mut list_state = ListState::default();
    if state.finding_count() > 0 {
        list_state.select(Some(state.selected_index));
    }

    let list = List::new(findings_list_items(scan_result))
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

    let detail = Paragraph::new(finding_detail_text(scan_result, state))
        .block(
            Block::default()
                .title(findings_detail_title(state.findings_focus))
                .borders(Borders::ALL)
                .border_style(focus_border_style(
                    state.findings_focus == FindingsFocus::Detail,
                )),
        )
        .wrap(Wrap { trim: true })
        .scroll((state.detail_scroll, 0));

    frame.render_stateful_widget(list, content[0], &mut list_state);
    frame.render_widget(detail, content[1]);
    frame.render_widget(findings_footer(state.findings_focus), layout[2]);
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
    ])))
    .alignment(Alignment::Center)
    .block(Block::default().borders(Borders::TOP | Borders::BOTTOM))
}

fn render_server_status_panel(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    scan_result: &ScanResult,
) {
    let mut lines = vec![
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
        load_line(scan_result),
        Line::raw(String::new()),
        Line::styled(
            t!("app.server.services_heading").into_owned(),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
    ];

    if scan_result.metadata.services.is_empty() {
        lines.push(Line::raw(t!("app.server.no_services").into_owned()));
    } else {
        for service in scan_result.metadata.services.iter().take(4) {
            lines.push(Line::styled(
                format!("* {}", service.name),
                Style::default().fg(Color::Green),
            ));
            lines.push(Line::raw(format!(
                "  {}",
                service
                    .image
                    .clone()
                    .unwrap_or_else(|| t!("app.server.no_image").into_owned())
            )));
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
    }

    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .block(
                Block::default()
                    .title(t!("app.panel.server_status").into_owned())
                    .borders(Borders::ALL)
                    .border_style(panel_border_style()),
            )
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_scan_results_panel(frame: &mut ratatui::Frame<'_>, area: Rect, scan_result: &ScanResult) {
    let mut lines = result_summary_lines(scan_result);
    lines.push(Line::raw(String::new()));
    lines.extend(severity_total_lines(scan_result));

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

    if !scan_result.metadata.warnings.is_empty() {
        lines.push(Line::raw(String::new()));
        lines.push(Line::styled(
            t!("app.result.warnings_heading").into_owned(),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ));
        for warning in scan_result.metadata.warnings.iter().take(2) {
            lines.push(Line::raw(format!("- {}", truncate_text(warning, 52))));
        }
    }

    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .block(
                Block::default()
                    .title(t!("app.panel.scan_results").into_owned())
                    .borders(Borders::ALL)
                    .border_style(panel_border_style()),
            )
            .wrap(Wrap { trim: true }),
        area,
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

    let bar_width = inner.width.saturating_sub(22).max(8) as usize;
    let mut lines = vec![score_line(
        t!("app.score.overall").into_owned(),
        scan_result.score_report.overall,
        bar_width,
        true,
    )];
    lines.push(Line::raw(String::new()));

    for axis in Axis::ALL {
        let score = scan_result
            .score_report
            .axis_scores
            .get(&axis)
            .copied()
            .unwrap_or(100);
        lines.push(score_line(axis_label(axis), score, bar_width, false));
    }

    frame.render_widget(
        Paragraph::new(Text::from(lines)).wrap(Wrap { trim: false }),
        inner,
    );
}

fn render_fix_paths_panel(frame: &mut ratatui::Frame<'_>, area: Rect, scan_result: &ScanResult) {
    let mut lines = remediation_lines(scan_result);
    if lines.is_empty() {
        lines.push(Line::raw(t!("app.fix.none").into_owned()));
    }

    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .block(
                Block::default()
                    .title(t!("app.panel.fix_paths").into_owned())
                    .borders(Borders::ALL)
                    .border_style(panel_border_style()),
            )
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn overview_footer() -> Paragraph<'static> {
    Paragraph::new(Text::from(Line::from(vec![
        hint_span("q", t!("app.footer.quit").into_owned()),
        Span::raw("  "),
        hint_span("Enter", t!("app.footer.findings").into_owned()),
        Span::raw("  "),
        hint_span("--json", t!("app.footer.json").into_owned()),
    ])))
    .alignment(Alignment::Left)
    .block(Block::default().borders(Borders::TOP))
}

fn findings_header(scan_result: &ScanResult, state: &AppState) -> Paragraph<'static> {
    let text = if state.finding_count() == 0 {
        t!("app.finding.empty_status").into_owned()
    } else {
        t!(
            "app.finding.status",
            index = state.selected_index + 1,
            count = state.finding_count(),
            focus = focus_label(state.findings_focus)
        )
        .into_owned()
    };

    Paragraph::new(Text::from(vec![
        Line::styled(
            t!("app.finding.header").into_owned(),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Line::raw(format!("{} | {}", text, compose_status(scan_result))),
    ]))
    .block(
        Block::default()
            .title(t!("app.panel.status").into_owned())
            .borders(Borders::ALL),
    )
    .wrap(Wrap { trim: true })
}

fn findings_footer(focus: FindingsFocus) -> Paragraph<'static> {
    let movement = match focus {
        FindingsFocus::List => t!("app.hint.list_move").into_owned(),
        FindingsFocus::Detail => t!("app.hint.detail_scroll").into_owned(),
    };

    Paragraph::new(Text::from(vec![
        Line::raw(movement),
        Line::raw(t!("app.hint.switch_focus").into_owned()),
        Line::raw(t!("app.hint.back_overview").into_owned()),
    ]))
    .block(Block::default().borders(Borders::TOP))
    .wrap(Wrap { trim: true })
}

fn findings_list_items(scan_result: &ScanResult) -> Vec<ListItem<'static>> {
    if scan_result.findings.is_empty() {
        return vec![ListItem::new(t!("app.finding.empty_title").into_owned())];
    }

    sorted_finding_indices(scan_result)
        .into_iter()
        .filter_map(|index| scan_result.findings.get(index))
        .map(|finding| {
            let title = format!(
                "[{}] {}",
                severity_short_label(finding.severity),
                finding.title
            );
            let meta = format!(
                "{} | {} | {}",
                source_label(finding.source),
                scope_label(finding.scope),
                finding.subject
            );

            ListItem::new(Text::from(vec![
                Line::styled(
                    title,
                    severity_style(finding.severity).add_modifier(Modifier::BOLD),
                ),
                Line::raw(meta),
            ]))
        })
        .collect()
}

fn finding_detail_text(scan_result: &ScanResult, state: &AppState) -> Text<'static> {
    let Some(finding) = state.selected_finding(scan_result) else {
        return Text::from(vec![
            Line::styled(
                t!("app.finding.empty_title").into_owned(),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Line::raw(t!("app.finding.empty_description").into_owned()),
        ]);
    };

    let mut lines = vec![
        Line::styled(
            finding.title.clone(),
            severity_style(finding.severity).add_modifier(Modifier::BOLD),
        ),
        Line::raw(format!(
            "{} | {} | {}",
            source_label(finding.source),
            scope_label(finding.scope),
            finding.subject
        )),
    ];

    if let Some(service) = &finding.related_service {
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

fn result_summary_lines(scan_result: &ScanResult) -> Vec<Line<'static>> {
    let rows = result_summary_rows(scan_result);
    if rows.is_empty() {
        return vec![Line::raw(t!("app.result.none").into_owned())];
    }

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

            Line::from(vec![
                Span::styled("* ", Style::default().fg(Color::Green)),
                Span::raw(format!("{: <16}", row.label)),
                Span::styled(
                    format!("[{status_text}]"),
                    status_style.add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!("  {}", findings_count_label(row.count))),
            ])
        })
        .collect()
}

fn severity_total_lines(scan_result: &ScanResult) -> Vec<Line<'static>> {
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

    vec![
        Line::raw(format!("Total: {} findings", scan_result.findings.len())),
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

fn remediation_lines(scan_result: &ScanResult) -> Vec<Line<'static>> {
    sorted_finding_indices(scan_result)
        .into_iter()
        .take(4)
        .filter_map(|index| scan_result.findings.get(index))
        .map(|finding| {
            let (label, style) = remediation_badge(finding.remediation);
            let text = truncate_text(
                if finding.how_to_fix.trim().is_empty() {
                    &finding.title
                } else {
                    &finding.how_to_fix
                },
                46,
            );

            Line::from(vec![
                Span::styled(format!("[{}]", label), style.add_modifier(Modifier::BOLD)),
                Span::raw("  "),
                Span::raw(text),
            ])
        })
        .collect()
}

fn score_line(label: String, score: u8, bar_width: usize, emphasize: bool) -> Line<'static> {
    let filled = ((score as usize * bar_width) / 100).min(bar_width);
    let empty = bar_width.saturating_sub(filled);
    let label = format!("{label: <18}");
    let score_text = format!("{score: >3}");
    let filled_bar = "#".repeat(filled);
    let empty_bar = "-".repeat(empty);

    Line::from(vec![
        Span::styled(
            label,
            if emphasize {
                Style::default().add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            },
        ),
        Span::raw(" "),
        Span::styled(score_text, score_style(score).add_modifier(Modifier::BOLD)),
        Span::raw("  "),
        Span::styled(filled_bar, score_style(score)),
        Span::styled(empty_bar, Style::default().fg(Color::DarkGray)),
    ])
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

fn sorted_finding_indices(scan_result: &ScanResult) -> Vec<usize> {
    let mut indices = (0..scan_result.findings.len()).collect::<Vec<_>>();
    indices.sort_by(|left, right| {
        compare_findings(&scan_result.findings[*left], &scan_result.findings[*right])
    });
    indices
}

fn compare_findings(left: &Finding, right: &Finding) -> Ordering {
    severity_rank(left.severity)
        .cmp(&severity_rank(right.severity))
        .then_with(|| left.title.cmp(&right.title))
        .then_with(|| source_label(left.source).cmp(&source_label(right.source)))
        .then_with(|| scope_label(left.scope).cmp(&scope_label(right.scope)))
        .then_with(|| left.subject.cmp(&right.subject))
        .then_with(|| left.id.cmp(&right.id))
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

fn load_line(scan_result: &ScanResult) -> Line<'static> {
    let load = scan_result
        .metadata
        .host_runtime
        .as_ref()
        .and_then(|runtime| runtime.load_average.clone())
        .unwrap_or_else(|| t!("app.server.not_available").into_owned());

    let bar = load_bar(scan_result).unwrap_or_else(|| String::from("----------"));

    Line::from(vec![
        Span::styled(
            format!("{:<14}", t!("app.server.load").into_owned()),
            Style::default().fg(Color::Cyan),
        ),
        Span::raw(load),
        Span::raw(" "),
        Span::styled(bar, Style::default().fg(Color::Green)),
    ])
}

fn load_bar(scan_result: &ScanResult) -> Option<String> {
    let runtime = scan_result.metadata.host_runtime.as_ref()?;
    let first = runtime
        .load_average
        .as_deref()?
        .split_whitespace()
        .next()?
        .parse::<f32>()
        .ok()?;
    let filled = ((first / 2.0) * 10.0).clamp(0.0, 10.0).round() as usize;

    Some(format!("{}{}", "#".repeat(filled), "-".repeat(10 - filled)))
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

fn severity_short_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "CRIT",
        Severity::High => "HIGH",
        Severity::Medium => "MED",
        Severity::Low => "LOW",
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

fn remediation_badge(remediation: RemediationKind) -> (&'static str, Style) {
    match remediation {
        RemediationKind::Safe => ("SAFE", Style::default().fg(Color::Green)),
        RemediationKind::Guided => ("GUIDED", Style::default().fg(Color::Yellow)),
        RemediationKind::None => ("MANUAL", Style::default().fg(Color::Blue)),
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

    #[test]
    fn overview_navigation_opens_findings() {
        let mut state = AppState::new(&sample_result());

        let should_exit = handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, crossterm::event::KeyModifiers::NONE),
        );

        assert!(!should_exit);
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
            KeyEvent::new(KeyCode::Down, crossterm::event::KeyModifiers::NONE),
        );
        assert_eq!(state.selected_index, 1);

        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Tab, crossterm::event::KeyModifiers::NONE),
        );
        assert_eq!(state.findings_focus, FindingsFocus::Detail);

        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::PageDown, crossterm::event::KeyModifiers::NONE),
        );
        assert!(state.detail_scroll > 0);

        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Esc, crossterm::event::KeyModifiers::NONE),
        );
        assert_eq!(state.screen, Screen::Overview);
    }

    #[test]
    fn overview_renders_mockup_like_sections_in_80x24() {
        let result = sample_result();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("terminal should build");

        terminal
            .draw(|frame| render(frame, &result, &AppState::new(&result)))
            .expect("overview should render");

        let content = buffer_to_string(terminal.backend());

        assert!(content.contains("Linux Self-Hosting Security Dashboard"));
        assert!(content.contains("Server Status"));
        assert!(content.contains("Scan Results"));
        assert!(content.contains("Security Scores"));
        assert!(content.contains("Fix Paths"));
        assert!(content.contains("61"));
        assert!(content.contains("adminer"));
        assert!(content.contains("home-server"));
        assert!(content.contains("24.0.7"));
        assert!(content.contains("14d 3h 22m"));
        assert!(content.contains("0.42 0.31 0.27"));
        assert!(content.contains("GUIDED"));
    }

    #[test]
    fn findings_view_renders_selected_finding_details() {
        let result = sample_result();
        let mut state = AppState::new(&result);
        state.open_findings();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("terminal should build");

        terminal
            .draw(|frame| render(frame, &result, &state))
            .expect("findings view should render");

        let content = buffer_to_string(terminal.backend());

        assert!(content.contains("Findings [list focus]"));
        assert!(content.contains("Detail"));
        assert!(content.contains("Admin interface is exposed publicly"));
        assert!(content.contains("Native Compose"));
        assert!(content.contains("Service"));
        assert!(content.contains("adminer"));
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
