use std::io;
use std::io::Read;
use std::path::Path;

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Padding, Paragraph, Wrap};
use rust_i18n::t;

use crate::domain::Finding;
use crate::fix::{
    self, FixAction, FixMode, FixPlan, FixResolutionMap, ReviewRequest, ReviewResolution,
};
use crate::tui::theme::{Theme, ThemePreset, panel_borders};

#[derive(Debug, Clone)]
pub struct InteractiveFixResult {
    pub plan: FixPlan,
    pub resolutions: FixResolutionMap,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FixReviewState {
    scroll: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReviewAction {
    Continue,
    Cancel,
    Accept,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ChoicePromptState {
    selected: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SecretPromptState {
    input: String,
    masked: bool,
}

pub fn run_interactive_fix_flow(
    compose_path: &Path,
    mode: FixMode,
    only_findings: Option<&[String]>,
    external_findings: &[Finding],
    confirm_apply: bool,
) -> Result<Option<InteractiveFixResult>, fix::FixError> {
    let mut resolutions = FixResolutionMap::new();

    loop {
        match fix::preview_with_external(
            compose_path,
            mode,
            only_findings,
            external_findings,
            &resolutions,
        ) {
            Ok(plan) => {
                if confirm_apply && plan.changed() && !run_fix_review(&plan)? {
                    return Ok(None);
                }
                return Ok(Some(InteractiveFixResult { plan, resolutions }));
            }
            Err(fix::FixError::ReviewRequired(requests)) => {
                for request in requests {
                    let resolution = match &request {
                        ReviewRequest::Choice { .. } => run_choice_prompt(&request)?,
                        ReviewRequest::SecretInput { .. } => run_secret_prompt(&request)?,
                    };
                    let Some(resolution) = resolution else {
                        return Ok(None);
                    };
                    resolutions.insert(request.finding_id().to_owned(), resolution);
                }
            }
            Err(error) => return Err(error),
        }
    }
}

pub fn run_fix_review(plan: &FixPlan) -> io::Result<bool> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let mut state = FixReviewState { scroll: 0 };

    let settings = crate::settings::load();
    let preset = settings
        .theme
        .as_deref()
        .and_then(ThemePreset::from_key)
        .unwrap_or(ThemePreset::TokyoNight);
    let theme = Theme::preset(preset);

    let result = run_event_loop(&mut terminal, plan, &mut state, &theme);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    plan: &FixPlan,
    state: &mut FixReviewState,
    theme: &Theme,
) -> io::Result<bool> {
    loop {
        terminal.draw(|frame| render(frame, plan, state, theme))?;

        match event::read()? {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                match apply_key_input(state, key.code) {
                    ReviewAction::Cancel => return Ok(false),
                    ReviewAction::Accept => return Ok(true),
                    ReviewAction::Continue => {}
                }
            }
            Event::Resize(_, _) => {}
            _ => {}
        }
    }
}

fn run_choice_prompt(request: &ReviewRequest) -> io::Result<Option<ReviewResolution>> {
    let ReviewRequest::Choice {
        title,
        description,
        options,
        ..
    } = request
    else {
        return Ok(None);
    };

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let mut state = ChoicePromptState { selected: 0 };

    let result = loop {
        terminal.draw(|frame| render_choice_prompt(frame, title, description, options, &state))?;
        match event::read()? {
            Event::Key(key) if key.kind == KeyEventKind::Press => match key.code {
                KeyCode::Esc | KeyCode::Char('q') => break Ok(None),
                KeyCode::Up | KeyCode::Char('k') => {
                    state.selected = state.selected.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    state.selected = (state.selected + 1).min(options.len().saturating_sub(1));
                }
                KeyCode::Enter => {
                    break Ok(Some(ReviewResolution::Choice(
                        options[state.selected].key.clone(),
                    )));
                }
                _ => {}
            },
            Event::Resize(_, _) => {}
            _ => {}
        }
    };

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

fn run_secret_prompt(request: &ReviewRequest) -> io::Result<Option<ReviewResolution>> {
    let ReviewRequest::SecretInput {
        title,
        description,
        suggested_value,
        ..
    } = request
    else {
        return Ok(None);
    };

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let mut state = SecretPromptState {
        input: suggested_value.clone(),
        masked: true,
    };

    let result = loop {
        terminal.draw(|frame| render_secret_prompt(frame, title, description, &state))?;
        match event::read()? {
            Event::Key(key) if key.kind == KeyEventKind::Press => match key.code {
                KeyCode::Esc | KeyCode::Char('q') => break Ok(None),
                KeyCode::Backspace => {
                    state.input.pop();
                }
                KeyCode::Tab => {
                    state.masked = !state.masked;
                }
                KeyCode::Enter if !state.input.trim().is_empty() => {
                    break Ok(Some(ReviewResolution::SecretValue(state.input.clone())));
                }
                KeyCode::Char('r')
                    if key
                        .modifiers
                        .contains(crossterm::event::KeyModifiers::CONTROL) =>
                {
                    state.input = generate_secret_value();
                }
                KeyCode::Char(c)
                    if !key
                        .modifiers
                        .contains(crossterm::event::KeyModifiers::CONTROL) =>
                {
                    state.input.push(c);
                }
                _ => {}
            },
            Event::Resize(_, _) => {}
            _ => {}
        }
    };

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

fn apply_key_input(state: &mut FixReviewState, code: KeyCode) -> ReviewAction {
    match code {
        KeyCode::Char('q') | KeyCode::Esc => ReviewAction::Cancel,
        KeyCode::Char('y') | KeyCode::Enter => ReviewAction::Accept,
        KeyCode::Down | KeyCode::Char('j') => {
            state.scroll = state.scroll.saturating_add(1);
            ReviewAction::Continue
        }
        KeyCode::Up | KeyCode::Char('k') => {
            state.scroll = state.scroll.saturating_sub(1);
            ReviewAction::Continue
        }
        KeyCode::PageDown => {
            state.scroll = state.scroll.saturating_add(8);
            ReviewAction::Continue
        }
        KeyCode::PageUp => {
            state.scroll = state.scroll.saturating_sub(8);
            ReviewAction::Continue
        }
        _ => ReviewAction::Continue,
    }
}

fn clamp_scroll(scroll: u16, diff_lines: usize, diff_height: u16) -> u16 {
    let max_scroll = diff_lines
        .saturating_sub(diff_height as usize)
        .min(u16::MAX as usize) as u16;
    scroll.min(max_scroll)
}

fn generate_secret_value() -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
    const SECRET_LENGTH: usize = 24;

    let mut bytes = [0_u8; SECRET_LENGTH];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .is_err()
    {
        bytes.copy_from_slice(b"hostveil-review-secret!!");
    }

    bytes
        .iter()
        .map(|byte| ALPHABET[*byte as usize % ALPHABET.len()] as char)
        .collect()
}

fn render(
    frame: &mut ratatui::Frame<'_>,
    plan: &FixPlan,
    state: &mut FixReviewState,
    theme: &Theme,
) {
    let diff_lines = plan.diff_preview.lines().count();

    let mut summary = Vec::<Line>::new();
    summary.push(Line::from(vec![
        Span::styled(
            t!("app.fix.file_label").into_owned(),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw(": "),
        Span::raw(plan.compose_file.display().to_string()),
    ]));

    if !plan.auto_applied.is_empty() {
        summary.push(Line::raw(""));
        summary.push(Line::from(vec![
            Span::styled(
                format!("[{}] ", t!("remediation.auto").into_owned()),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(t!("app.fix.auto_plan", count = plan.auto_applied.len()).into_owned()),
        ]));
        for proposal in &plan.auto_applied {
            summary.push(Line::from(vec![
                Span::raw("  • "),
                Span::styled(
                    &proposal.service,
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::raw(": "),
                Span::raw(&proposal.summary),
            ]));
        }
    }

    if !plan.review_applied.is_empty() {
        summary.push(Line::raw(""));
        summary.push(Line::from(vec![
            Span::styled(
                format!("[{}] ", t!("remediation.review").into_owned()),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(t!("app.fix.review_plan", count = plan.review_applied.len()).into_owned()),
        ]));
        for proposal in &plan.review_applied {
            summary.push(Line::from(vec![
                Span::raw("  • "),
                Span::styled(
                    &proposal.service,
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::raw(": "),
                Span::raw(&proposal.summary),
            ]));
        }
    }

    if !plan.host_actions.is_empty() {
        summary.push(Line::raw(""));
        summary.push(Line::from(vec![
            Span::styled(
                " [HOST EDIT] ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(t!("app.fix.host_edit_plan", count = plan.host_actions.len()).into_owned()),
        ]));
        for action in &plan.host_actions {
            if let FixAction::HostEdit {
                path,
                summary: action_summary,
                ..
            } = action
            {
                summary.push(Line::from(vec![
                    Span::raw("  • "),
                    Span::styled(
                        path.display().to_string(),
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(": "),
                    Span::raw(action_summary),
                ]));
            }
        }
    }

    if !plan.system_actions.is_empty() {
        summary.push(Line::raw(""));
        summary.push(Line::from(vec![
            Span::styled(
                " [SHELL] ",
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(t!("app.fix.shell_plan", count = plan.system_actions.len()).into_owned()),
        ]));
        for action in &plan.system_actions {
            if let FixAction::ShellCommand {
                command,
                summary: action_summary,
                ..
            } = action
            {
                summary.push(Line::from(vec![
                    Span::raw("  • "),
                    Span::styled(
                        t!("app.fix.shell_label").into_owned(),
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(": "),
                    Span::raw(action_summary),
                ]));
                summary.push(Line::from(vec![
                    Span::raw("    "),
                    Span::styled(format!("$ {}", command), Style::default().fg(Color::Cyan)),
                ]));
            }
        }
    }

    if !plan.compose_actions.is_empty() {
        summary.push(Line::raw(""));
        summary.push(Line::from(vec![
            Span::styled(
                " [COMPOSE] ",
                Style::default()
                    .fg(Color::Blue)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(
                t!(
                    "app.fix.compose_edit_plan",
                    count = plan.compose_actions.len()
                )
                .into_owned(),
            ),
        ]));
        for action in &plan.compose_actions {
            if let FixAction::ComposeEdit {
                service,
                summary: action_summary,
                ..
            } = action
            {
                summary.push(Line::from(vec![
                    Span::raw("  • "),
                    Span::styled(service, Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(": "),
                    Span::raw(action_summary),
                ]));
            }
        }
    }

    let summary_lines_count = summary.len();

    let footer_height = if theme.borders_enabled { 5 } else { 3 };

    let summary_widget = Paragraph::new(Text::from(summary))
        .wrap(Wrap { trim: true })
        .style(theme.panel_bg)
        .block(
            Block::default()
                .title(Line::from(t!("app.panel.fix_review").into_owned()).style(theme.title))
                .borders(panel_borders(theme))
                .border_style(theme.border)
                .style(theme.panel_bg)
                .padding(Padding::horizontal(1)),
        );

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .spacing(1)
        .constraints([
            Constraint::Length((summary_lines_count as u16 + 2).clamp(5, 20)),
            Constraint::Min(5),
            Constraint::Length(footer_height),
        ])
        .split(frame.area());

    // Fill surface background behind panels
    frame.render_widget(Block::default().style(theme.surface), frame.area());

    frame.render_widget(summary_widget, chunks[0]);

    let diff_text = Text::from(
        plan.diff_preview
            .lines()
            .map(|line| {
                let style = if line.starts_with('+') {
                    Style::default().fg(Color::Green)
                } else if line.starts_with('-') {
                    Style::default().fg(Color::Red)
                } else if line.starts_with("@@") {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default()
                };
                Line::styled(line.to_owned(), style)
            })
            .collect::<Vec<_>>(),
    );

    let diff_height = chunks[1].height.saturating_sub(2);
    state.scroll = clamp_scroll(state.scroll, diff_lines, diff_height);

    let diff_widget = Paragraph::new(diff_text)
        .scroll((state.scroll, 0))
        .wrap(Wrap { trim: false })
        .style(theme.panel_bg)
        .block(
            Block::default()
                .title(Line::from(t!("app.panel.fix_diff").into_owned()).style(theme.title))
                .borders(panel_borders(theme))
                .border_style(theme.border)
                .style(theme.panel_bg)
                .padding(Padding::horizontal(1)),
        );
    frame.render_widget(diff_widget, chunks[1]);

    let hints = vec![
        Line::from(t!("app.hint.fix_review_scroll").into_owned()),
        Line::from(t!("app.hint.fix_review_apply").into_owned()),
        Line::from(t!("app.hint.fix_review_cancel").into_owned()),
    ];
    let hints_widget = Paragraph::new(Text::from(hints))
        .wrap(Wrap { trim: true })
        .style(theme.panel_bg)
        .block(
            Block::default()
                .title(Line::from(t!("app.panel.hints").into_owned()).style(theme.title))
                .borders(panel_borders(theme))
                .border_style(theme.border)
                .style(theme.panel_bg)
                .padding(Padding::horizontal(1)),
        );
    frame.render_widget(hints_widget, chunks[2]);
}

fn render_choice_prompt(
    frame: &mut ratatui::Frame<'_>,
    title: &str,
    description: &str,
    options: &[crate::fix::ReviewChoiceOption],
    state: &ChoicePromptState,
) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Min(8),
            Constraint::Length(3),
        ])
        .split(area);

    let panel_bg = Style::default().bg(Color::Rgb(28, 28, 38));
    let title_style = Style::default()
        .fg(Color::Rgb(122, 162, 247))
        .add_modifier(Modifier::BOLD);

    let header = Paragraph::new(Text::from(vec![
        Line::styled(
            title.to_owned(),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Line::raw(""),
        Line::raw(description.to_owned()),
    ]))
    .wrap(Wrap { trim: true })
    .style(panel_bg)
    .block(
        Block::default()
            .title(Line::from(t!("app.panel.fix_review").into_owned()).style(title_style))
            .borders(Borders::NONE)
            .style(panel_bg)
            .padding(Padding::horizontal(1)),
    );
    frame.render_widget(header, chunks[0]);

    let mut lines = Vec::new();
    for (index, option) in options.iter().enumerate() {
        let selected = index == state.selected;
        let style = if selected {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        lines.push(Line::styled(format!("> {}", option.label), style));
        lines.push(Line::raw(format!("  {}", option.description)));
        lines.push(Line::raw(""));
    }

    let options_widget = Paragraph::new(Text::from(lines))
        .wrap(Wrap { trim: true })
        .style(panel_bg)
        .block(
            Block::default()
                .title(Line::from(t!("app.fix.review_options").into_owned()).style(title_style))
                .borders(Borders::NONE)
                .style(panel_bg)
                .padding(Padding::horizontal(1)),
        );
    frame.render_widget(options_widget, chunks[1]);

    let hints = Paragraph::new(Text::from(vec![
        Line::raw(t!("app.hint.review_choice_move").into_owned()),
        Line::raw(t!("app.hint.review_choice_accept").into_owned()),
        Line::raw(t!("app.hint.review_choice_cancel").into_owned()),
    ]))
    .wrap(Wrap { trim: true })
    .style(panel_bg)
    .block(
        Block::default()
            .borders(Borders::NONE)
            .style(panel_bg)
            .padding(Padding::horizontal(1)),
    );
    frame.render_widget(hints, chunks[2]);
}

fn render_secret_prompt(
    frame: &mut ratatui::Frame<'_>,
    title: &str,
    description: &str,
    state: &SecretPromptState,
) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Length(5),
            Constraint::Length(4),
        ])
        .split(area);

    let panel_bg = Style::default().bg(Color::Rgb(28, 28, 38));
    let title_style = Style::default()
        .fg(Color::Rgb(122, 162, 247))
        .add_modifier(Modifier::BOLD);

    let header = Paragraph::new(Text::from(vec![
        Line::styled(
            title.to_owned(),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Line::raw(""),
        Line::raw(description.to_owned()),
    ]))
    .wrap(Wrap { trim: true })
    .style(panel_bg)
    .block(
        Block::default()
            .title(Line::from(t!("app.panel.fix_review").into_owned()).style(title_style))
            .borders(Borders::NONE)
            .style(panel_bg)
            .padding(Padding::horizontal(1)),
    );
    frame.render_widget(header, chunks[0]);

    let visible_value = if state.masked {
        "*".repeat(state.input.chars().count())
    } else {
        state.input.clone()
    };
    let input_widget = Paragraph::new(Text::from(vec![
        Line::styled(visible_value, Style::default().fg(Color::Yellow)),
        Line::raw(""),
        Line::raw(t!("app.fix.review_secret_mask_toggle").into_owned()),
    ]))
    .wrap(Wrap { trim: false })
    .style(panel_bg)
    .block(
        Block::default()
            .title(Line::from(t!("app.fix.review_secret_value").into_owned()).style(title_style))
            .borders(Borders::NONE)
            .style(panel_bg)
            .padding(Padding::horizontal(1)),
    );
    frame.render_widget(input_widget, chunks[1]);

    let hints = Paragraph::new(Text::from(vec![
        Line::raw(t!("app.hint.review_secret_accept").into_owned()),
        Line::raw(t!("app.hint.review_secret_regenerate").into_owned()),
        Line::raw(t!("app.hint.review_secret_cancel").into_owned()),
    ]))
    .wrap(Wrap { trim: true })
    .style(panel_bg)
    .block(
        Block::default()
            .borders(Borders::NONE)
            .style(panel_bg)
            .padding(Padding::horizontal(1)),
    );
    frame.render_widget(hints, chunks[2]);
}

#[cfg(test)]
mod tests {
    use crossterm::event::KeyCode;
    use ratatui::backend::Backend;

    use super::{
        ChoicePromptState, FixReviewState, ReviewAction, SecretPromptState, apply_key_input,
        clamp_scroll, render, render_choice_prompt, render_secret_prompt,
    };
    use crate::fix::{FixPlan, ReviewChoiceOption};
    use crate::tui::theme::{Theme, ThemePreset};

    #[test]
    fn apply_key_input_handles_accept_and_cancel_shortcuts() {
        let mut state = FixReviewState { scroll: 0 };

        assert_eq!(
            apply_key_input(&mut state, KeyCode::Char('y')),
            ReviewAction::Accept
        );
        assert_eq!(
            apply_key_input(&mut state, KeyCode::Enter),
            ReviewAction::Accept
        );
        assert_eq!(
            apply_key_input(&mut state, KeyCode::Char('q')),
            ReviewAction::Cancel
        );
        assert_eq!(
            apply_key_input(&mut state, KeyCode::Esc),
            ReviewAction::Cancel
        );
    }

    #[test]
    fn apply_key_input_updates_scroll_with_navigation_keys() {
        let mut state = FixReviewState { scroll: 0 };

        assert_eq!(
            apply_key_input(&mut state, KeyCode::Down),
            ReviewAction::Continue
        );
        assert_eq!(state.scroll, 1);

        assert_eq!(
            apply_key_input(&mut state, KeyCode::Char('j')),
            ReviewAction::Continue
        );
        assert_eq!(state.scroll, 2);

        assert_eq!(
            apply_key_input(&mut state, KeyCode::PageDown),
            ReviewAction::Continue
        );
        assert_eq!(state.scroll, 10);

        assert_eq!(
            apply_key_input(&mut state, KeyCode::Up),
            ReviewAction::Continue
        );
        assert_eq!(state.scroll, 9);

        assert_eq!(
            apply_key_input(&mut state, KeyCode::Char('k')),
            ReviewAction::Continue
        );
        assert_eq!(state.scroll, 8);

        assert_eq!(
            apply_key_input(&mut state, KeyCode::PageUp),
            ReviewAction::Continue
        );
        assert_eq!(state.scroll, 0);
    }

    #[test]
    fn clamp_scroll_limits_scroll_to_visible_diff_range() {
        assert_eq!(clamp_scroll(50, 10, 4), 6);
        assert_eq!(clamp_scroll(4, 3, 10), 0);
        assert_eq!(clamp_scroll(u16::MAX, usize::MAX, 0), u16::MAX);
    }

    use crate::fix::FixProposal;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use std::path::PathBuf;

    fn sample_plan(auto_count: usize, review_count: usize) -> FixPlan {
        let auto_applied: Vec<_> = (0..auto_count)
            .map(|i| FixProposal {
                service: format!("svc-{i}"),
                summary: format!("auto fix {i}"),
                remediation: crate::domain::RemediationKind::Auto,
            })
            .collect();
        let review_applied: Vec<_> = (0..review_count)
            .map(|i| FixProposal {
                service: format!("svc-{i}"),
                summary: format!("review fix {i}"),
                remediation: crate::domain::RemediationKind::Review,
            })
            .collect();
        FixPlan {
            compose_file: PathBuf::from("/srv/demo/docker-compose.yml"),
            diff_preview: if auto_count == 0 && review_count == 0 {
                String::new()
            } else {
                format!(
                    "--- /srv/demo/docker-compose.yml\n+++ /srv/demo/docker-compose.yml\n@@ -1,3 +1,5 @@\n{}\n  web:\n    image: nginx:stable\n",
                    if auto_count > 0 {
                        "+    ports:\n+      - 127.0.0.1:8080:80"
                    } else {
                        ""
                    }
                )
            },
            updated_text: String::new(),
            backup_path: None,
            auto_applied,
            review_applied,
            host_actions: Vec::new(),
            system_actions: Vec::new(),
            compose_actions: Vec::new(),
        }
    }

    fn sample_theme() -> Theme {
        Theme::preset(ThemePreset::TokyoNight)
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

    #[test]
    fn renders_auto_and_review_summary() {
        let plan = sample_plan(1, 1);
        let mut state = FixReviewState { scroll: 0 };
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("terminal should build");

        let theme = sample_theme();
        terminal
            .draw(|frame| render(frame, &plan, &mut state, &theme))
            .expect("fix review should render");

        let content = buffer_to_string(terminal.backend());
        assert!(
            content.contains("auto fix 0"),
            "auto proposal should be visible"
        );
        assert!(
            content.contains("review fix 0"),
            "review proposal should be visible"
        );
        assert!(
            content.contains("/srv/demo/docker-compose.yml"),
            "compose file path should be visible"
        );
    }

    #[test]
    fn renders_diff_colors() {
        let plan = sample_plan(1, 0);
        let mut state = FixReviewState { scroll: 0 };
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("terminal should build");

        let theme = sample_theme();
        terminal
            .draw(|frame| render(frame, &plan, &mut state, &theme))
            .expect("fix review should render");

        let buffer = terminal.backend().buffer();
        let area = terminal
            .backend()
            .size()
            .expect("backend should have a size");

        // Find a cell containing '+' and assert it's green
        let mut found_green = false;
        let mut found_cyan = false;
        for y in 0..area.height {
            for x in 0..area.width {
                let cell = &buffer[(x, y)];
                if cell.symbol() == "+" && cell.style().fg == Some(ratatui::style::Color::Green) {
                    found_green = true;
                }
                if cell.symbol() == "@" && cell.style().fg == Some(ratatui::style::Color::Cyan) {
                    found_cyan = true;
                }
            }
        }
        assert!(found_green, "diff addition lines should be colored green");
        assert!(found_cyan, "diff hunk headers should be colored cyan");
    }

    #[test]
    fn renders_hint_footer() {
        let plan = sample_plan(1, 0);
        let mut state = FixReviewState { scroll: 0 };
        let mut terminal = Terminal::new(TestBackend::new(120, 24)).expect("terminal should build");

        let theme = sample_theme();
        terminal
            .draw(|frame| render(frame, &plan, &mut state, &theme))
            .expect("fix review should render");

        let content = buffer_to_string(terminal.backend());
        // Hints widget has 3 rows total (1 inner row after borders), so only the first hint line is visible
        assert!(
            content.contains("Up/Down or PgUp/PgDn"),
            "scroll hint should be visible: {}",
            content
        );
        assert!(
            content.contains("Hints"),
            "hints panel title should be visible"
        );
    }

    #[test]
    fn empty_plan_renders_without_panic() {
        let plan = sample_plan(0, 0);
        let mut state = FixReviewState { scroll: 0 };
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("terminal should build");

        let theme = sample_theme();
        terminal
            .draw(|frame| render(frame, &plan, &mut state, &theme))
            .expect("empty fix review should render");

        let content = buffer_to_string(terminal.backend());
        assert!(content.contains("/srv/demo/docker-compose.yml"));
    }

    fn find_cell_with_symbol(backend: &TestBackend, symbol: &str) -> Option<ratatui::buffer::Cell> {
        let area = backend.size().expect("backend should have a size");
        let buffer = backend.buffer();
        for y in 0..area.height {
            for x in 0..area.width {
                let cell = &buffer[(x, y)];
                if cell.symbol() == symbol {
                    return Some(cell.clone());
                }
            }
        }
        None
    }

    #[test]
    fn renders_choice_prompt_with_highlighted_option() {
        let options = vec![
            ReviewChoiceOption {
                key: String::from("opt-a"),
                label: String::from("Option A"),
                description: String::from("First option"),
            },
            ReviewChoiceOption {
                key: String::from("opt-b"),
                label: String::from("Option B"),
                description: String::from("Second option"),
            },
        ];
        let state = ChoicePromptState { selected: 0 };
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("terminal should build");

        terminal
            .draw(|frame| {
                render_choice_prompt(
                    frame,
                    "Choose a review path",
                    "Select how to proceed.",
                    &options,
                    &state,
                )
            })
            .expect("choice prompt should render");

        let content = buffer_to_string(terminal.backend());
        assert!(
            content.contains("Choose a review path"),
            "title should be visible"
        );
        assert!(
            content.contains("Select how to proceed."),
            "description should be visible"
        );
        assert!(
            content.contains("Option A"),
            "option label should be visible"
        );
        assert!(
            content.contains("First option"),
            "option description should be visible"
        );

        // The selected option row starts with "> Option A" and should be highlighted
        let cell = find_cell_with_symbol(terminal.backend(), ">")
            .expect("> symbol should be present for selected option");
        assert_eq!(
            cell.style().fg,
            Some(ratatui::style::Color::Black),
            "highlighted option should have black foreground"
        );
        assert_eq!(
            cell.style().bg,
            Some(ratatui::style::Color::Cyan),
            "highlighted option should have cyan background"
        );
        assert!(
            cell.style()
                .add_modifier
                .contains(ratatui::style::Modifier::BOLD),
            "highlighted option should be bold"
        );
    }

    #[test]
    fn renders_secret_prompt_with_masked_value() {
        let state = SecretPromptState {
            input: String::from("secret123"),
            masked: true,
        };
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("terminal should build");

        terminal
            .draw(|frame| {
                render_secret_prompt(
                    frame,
                    "Provide a secret value",
                    "Enter a secure value.",
                    &state,
                )
            })
            .expect("secret prompt should render");

        let content = buffer_to_string(terminal.backend());
        assert!(
            content.contains("Provide a secret value"),
            "title should be visible"
        );
        assert!(
            content.contains("Enter a secure value."),
            "description should be visible"
        );
        assert!(
            content.contains("*********"),
            "masked value should show asterisks"
        );
        assert!(
            !content.contains("secret123"),
            "raw secret should not be visible when masked"
        );
    }

    #[test]
    fn renders_secret_prompt_with_unmasked_value() {
        let state = SecretPromptState {
            input: String::from("visible-value"),
            masked: false,
        };
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("terminal should build");

        terminal
            .draw(|frame| {
                render_secret_prompt(
                    frame,
                    "Provide a secret value",
                    "Enter a secure value.",
                    &state,
                )
            })
            .expect("secret prompt should render");

        let content = buffer_to_string(terminal.backend());
        assert!(
            content.contains("visible-value"),
            "unmasked value should be visible"
        );
        assert!(
            !content.contains("*************"),
            "asterisks should not appear when unmasked"
        );
    }

    #[test]
    fn renders_compose_actions_when_present() {
        let mut plan = sample_plan(0, 0);
        plan.compose_actions = vec![crate::fix::FixAction::ComposeEdit {
            service: "web".to_string(),
            summary: "add healthcheck".to_string(),
            diff: "+  healthcheck:\n+    test: [\"CMD\"]\n".to_string(),
        }];
        let mut state = FixReviewState { scroll: 0 };
        let theme = sample_theme();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("terminal");
        terminal
            .draw(|frame| render(frame, &plan, &mut state, &theme))
            .expect("fix review with compose actions should render");
        let content = buffer_to_string(terminal.backend());
        assert!(
            content.contains("[COMPOSE]"),
            "compose actions section should have [COMPOSE] label"
        );
        assert!(
            content.contains("add healthcheck"),
            "compose action summary should be visible"
        );
        assert!(
            content.contains("web"),
            "compose action service should be visible"
        );
    }

    #[test]
    fn renders_host_edit_section() {
        let mut plan = sample_plan(0, 0);
        plan.host_actions = vec![crate::fix::FixAction::HostEdit {
            path: PathBuf::from("/etc/ssh/sshd_config"),
            summary: "disable root login".to_string(),
            original_content: String::new(),
            updated_content: "PermitRootLogin no\n".to_string(),
            mode: None,
        }];
        let mut state = FixReviewState { scroll: 0 };
        let theme = sample_theme();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("terminal");
        terminal
            .draw(|frame| render(frame, &plan, &mut state, &theme))
            .expect("fix review with host edit should render");
        let content = buffer_to_string(terminal.backend());
        assert!(
            content.contains("[HOST EDIT]"),
            "host edit section should have [HOST EDIT] label"
        );
        assert!(
            content.contains("disable root login"),
            "host edit summary should be visible"
        );
        assert!(
            content.contains("sshd_config"),
            "host edit path should be visible"
        );
    }

    #[test]
    fn renders_system_actions_section() {
        let mut plan = sample_plan(0, 0);
        plan.system_actions = vec![crate::fix::FixAction::ShellCommand {
            command: "systemctl enable fail2ban".to_string(),
            summary: "enable fail2ban".to_string(),
            rollback: None,
        }];
        let mut state = FixReviewState { scroll: 0 };
        let theme = sample_theme();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("terminal");
        terminal
            .draw(|frame| render(frame, &plan, &mut state, &theme))
            .expect("fix review with system actions should render");
        let content = buffer_to_string(terminal.backend());
        assert!(
            content.contains("[SHELL]"),
            "system actions section should have [SHELL] label"
        );
        assert!(
            content.contains("enable fail2ban"),
            "shell action summary should be visible"
        );
        assert!(
            content.contains("systemctl enable fail2ban"),
            "shell command should be visible"
        );
    }

    #[test]
    fn renders_all_action_sections_simultaneously() {
        let mut plan = sample_plan(1, 1);
        plan.host_actions = vec![crate::fix::FixAction::HostEdit {
            path: PathBuf::from("/etc/ssh/sshd_config"),
            summary: "disable root login".to_string(),
            original_content: String::new(),
            updated_content: "PermitRootLogin no\n".to_string(),
            mode: None,
        }];
        plan.system_actions = vec![crate::fix::FixAction::ShellCommand {
            command: "systemctl enable fail2ban".to_string(),
            summary: "enable fail2ban".to_string(),
            rollback: None,
        }];
        plan.compose_actions = vec![crate::fix::FixAction::ComposeEdit {
            service: "web".to_string(),
            summary: "add healthcheck".to_string(),
            diff: "+  healthcheck:\n".to_string(),
        }];
        let mut state = FixReviewState { scroll: 0 };
        let theme = sample_theme();
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).expect("terminal");
        terminal
            .draw(|frame| render(frame, &plan, &mut state, &theme))
            .expect("fix review with all sections should render");
        let content = buffer_to_string(terminal.backend());
        assert!(
            content.contains("[HOST EDIT]"),
            "host edit section should appear"
        );
        assert!(
            content.contains("[SHELL]"),
            "system actions section should appear"
        );
        assert!(
            content.contains("[COMPOSE]"),
            "compose actions section should appear"
        );
        assert!(content.contains("[AUTO]"), "auto section should appear");
        assert!(content.contains("[REVIEW]"), "review section should appear");
        assert!(content.contains("disable root login"), "host edit summary");
        assert!(content.contains("enable fail2ban"), "shell summary");
        assert!(content.contains("add healthcheck"), "compose summary");
    }

    #[test]
    fn host_edit_section_shows_yellow_label_color() {
        let mut plan = sample_plan(0, 0);
        plan.host_actions = vec![crate::fix::FixAction::HostEdit {
            path: PathBuf::from("/tmp/test.conf"),
            summary: "test config".to_string(),
            original_content: String::new(),
            updated_content: "val".to_string(),
            mode: None,
        }];
        let mut state = FixReviewState { scroll: 0 };
        let theme = sample_theme();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("terminal");
        terminal
            .draw(|frame| render(frame, &plan, &mut state, &theme))
            .expect("fix review with host edit should render");
        let buffer = terminal.backend().buffer();
        let area = terminal.backend().size().expect("size");
        // "[HOST EDIT]" label is rendered with Yellow fg.
        // Find a cell with `[` that has Yellow foreground near "HOST EDIT".
        let mut found = false;
        for y in 0..area.height {
            for x in 0..area.width.saturating_sub(10) {
                let snippet: String = (0..11).map(|dx| buffer[(x + dx, y)].symbol()).collect();
                if snippet == "[HOST EDIT]" {
                    // The entire span should be Yellow; check the `[` cell
                    if buffer[(x, y)].style().fg == Some(ratatui::style::Color::Yellow) {
                        found = true;
                    }
                }
            }
        }
        assert!(found, "[HOST EDIT] label should be rendered in Yellow");
    }

    #[test]
    fn shell_section_shows_magenta_label_color() {
        let mut plan = sample_plan(0, 0);
        plan.system_actions = vec![crate::fix::FixAction::ShellCommand {
            command: "echo test".to_string(),
            summary: "test shell".to_string(),
            rollback: None,
        }];
        let mut state = FixReviewState { scroll: 0 };
        let theme = sample_theme();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("terminal");
        terminal
            .draw(|frame| render(frame, &plan, &mut state, &theme))
            .expect("fix review with system actions should render");
        let buffer = terminal.backend().buffer();
        let area = terminal.backend().size().expect("size");
        let mut found = false;
        for y in 0..area.height {
            for x in 0..area.width.saturating_sub(7) {
                let snippet: String = (0..8).map(|dx| buffer[(x + dx, y)].symbol()).collect();
                if snippet == "[SHELL] "
                    && buffer[(x, y)].style().fg == Some(ratatui::style::Color::Magenta)
                {
                    found = true;
                }
            }
        }
        assert!(found, "[SHELL] label should be rendered in Magenta");
    }

    // ── run_interactive_fix_flow integration tests (non-TTY path) ──

    #[test]
    fn run_interactive_fix_flow_returns_plan_without_tty_when_confirm_is_false() {
        let dir = std::env::temp_dir().join(format!("hostveil-fix-flow-{}", std::process::id()));
        std::fs::create_dir_all(&dir).ok();
        let compose_path = dir.join("docker-compose.yml");
        std::fs::write(
            &compose_path,
            "services:\n  web:\n    image: nginx:latest\n    ports:\n      - \"80:80\"\n",
        )
        .expect("write compose");

        let native_finding = crate::domain::Finding {
            id: "host.ssh_root_login_enabled".to_string(),
            axis: crate::domain::Axis::HostHardening,
            severity: crate::domain::Severity::Medium,
            scope: crate::domain::Scope::Host,
            source: crate::domain::Source::NativeHost,
            subject: "host".to_string(),
            related_service: None,
            title: "test".to_string(),
            description: "test".to_string(),
            why_risky: "risky".to_string(),
            how_to_fix: "fix".to_string(),
            evidence: std::collections::BTreeMap::new(),
            remediation: crate::domain::RemediationKind::Review,
        };
        let external = vec![native_finding];

        let result = super::run_interactive_fix_flow(
            &compose_path,
            crate::fix::FixMode::AutoFix,
            None,
            &external,
            false,
        )
        .expect("fix flow should succeed");

        let result = result.expect("should return Some result");
        assert!(
            !result.plan.system_actions.is_empty(),
            "NativeHost finding should produce system_actions"
        );
        assert!(
            result.plan.system_actions[0]
                .summary()
                .contains("disable SSH root login"),
            "should be the root login action"
        );
        assert!(
            result.plan.changed(),
            "plan with system_actions should be changed"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn run_interactive_fix_flow_returns_empty_for_no_changes() {
        let dir =
            std::env::temp_dir().join(format!("hostveil-fix-flow-empty-{}", std::process::id()));
        std::fs::create_dir_all(&dir).ok();
        let compose_path = dir.join("docker-compose.yml");
        // Hardened compose — no native fixes needed
        std::fs::write(
            &compose_path,
            "services:\n  web:\n    image: nginx:stable\n    ports:\n      - \"127.0.0.1:8080:80\"\n",
        )
        .expect("write compose");

        let result = super::run_interactive_fix_flow(
            &compose_path,
            crate::fix::FixMode::AutoFix,
            None,
            &[], // no external findings
            false,
        )
        .expect("fix flow should succeed");

        let result = result.expect("should return Some result");
        // No external findings → no adapter actions regardless of native changes
        assert!(result.plan.system_actions.is_empty());
        assert!(result.plan.host_actions.is_empty());
        assert!(result.plan.compose_actions.is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }
}
