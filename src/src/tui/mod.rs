use std::io;

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Text};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::domain::ScanResult;
use crate::i18n;

#[derive(Debug, Clone, PartialEq, Eq)]
struct BootstrapCopy {
    title: String,
    status: String,
    summary_title: String,
    summary_lines: Vec<String>,
    quit_hint: String,
    json_hint: String,
    next_steps_title: String,
    next_steps: [String; 3],
}

pub fn run(scan_result: &ScanResult) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_event_loop(&mut terminal, scan_result);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    scan_result: &ScanResult,
) -> io::Result<()> {
    let copy = bootstrap_copy(scan_result);

    loop {
        terminal.draw(|frame| render_bootstrap(frame, &copy))?;

        if let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
            && matches!(key.code, KeyCode::Char('q') | KeyCode::Esc)
        {
            return Ok(());
        }
    }
}

fn render_bootstrap(frame: &mut ratatui::Frame<'_>, copy: &BootstrapCopy) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Length(6),
            Constraint::Min(6),
            Constraint::Length(4),
        ])
        .split(frame.area());

    let header = Paragraph::new(Text::from(vec![
        Line::styled(
            copy.title.as_str(),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Line::raw(copy.status.as_str()),
    ]))
    .block(
        Block::default()
            .title(i18n::tr("app.panel.status"))
            .borders(Borders::ALL),
    )
    .wrap(Wrap { trim: true });

    let summary = Paragraph::new(Text::from(
        copy.summary_lines
            .iter()
            .map(|line| Line::raw(line.as_str()))
            .collect::<Vec<_>>(),
    ))
    .block(
        Block::default()
            .title(copy.summary_title.as_str())
            .borders(Borders::ALL),
    )
    .wrap(Wrap { trim: true });

    let body = Paragraph::new(Text::from(vec![
        Line::styled(
            copy.next_steps_title.as_str(),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Line::raw(""),
        Line::raw(format!("1. {}", copy.next_steps[0])),
        Line::raw(format!("2. {}", copy.next_steps[1])),
        Line::raw(format!("3. {}", copy.next_steps[2])),
    ]))
    .block(Block::default().borders(Borders::ALL))
    .wrap(Wrap { trim: true });

    let footer = Paragraph::new(Text::from(vec![
        Line::raw(copy.quit_hint.as_str()),
        Line::raw(copy.json_hint.as_str()),
    ]))
    .block(
        Block::default()
            .title(i18n::tr("app.panel.hints"))
            .borders(Borders::ALL),
    )
    .wrap(Wrap { trim: true });

    frame.render_widget(header, layout[0]);
    frame.render_widget(summary, layout[1]);
    frame.render_widget(body, layout[2]);
    frame.render_widget(footer, layout[3]);
}

fn bootstrap_copy(scan_result: &ScanResult) -> BootstrapCopy {
    BootstrapCopy {
        title: i18n::tr("app.name"),
        status: compose_status(scan_result),
        summary_title: i18n::tr("app.summary.title"),
        summary_lines: compose_summary_lines(scan_result),
        quit_hint: i18n::tr("app.hint.quit"),
        json_hint: i18n::tr("app.hint.json"),
        next_steps_title: i18n::tr("app.panel.next_steps"),
        next_steps: [
            i18n::tr("app.panel.next_step_one"),
            i18n::tr("app.panel.next_step_two"),
            i18n::tr("app.panel.next_step_three"),
        ],
    }
}

fn compose_status(scan_result: &ScanResult) -> String {
    match &scan_result.metadata.compose_file {
        Some(path) => i18n::tr_status_compose_loaded(
            &path.display().to_string(),
            scan_result.metadata.service_count,
        ),
        None => i18n::tr("app.status.no_target"),
    }
}

fn compose_summary_lines(scan_result: &ScanResult) -> Vec<String> {
    let metadata = &scan_result.metadata;
    let mut lines = Vec::new();

    if let Some(path) = &metadata.compose_file {
        lines.push(i18n::tr_summary_compose_file(&path.display().to_string()));
    }
    if let Some(path) = &metadata.compose_root {
        lines.push(i18n::tr_summary_compose_root(&path.display().to_string()));
    }
    if metadata.loaded_files.is_empty() {
        lines.push(i18n::tr("app.summary.none"));
    } else {
        lines.push(i18n::tr_summary_loaded_files(metadata.loaded_files.len()));
        lines.push(i18n::tr_summary_service_count(metadata.service_count));
        lines.push(i18n::tr_summary_finding_count(scan_result.findings.len()));
        lines.push(i18n::tr_summary_overall_score(
            scan_result.score_report.overall,
        ));
    }

    lines
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::bootstrap_copy;
    use crate::domain::{ScanMetadata, ScanResult};

    #[test]
    fn bootstrap_copy_contains_expected_text() {
        let copy = bootstrap_copy(&ScanResult::default());

        assert_eq!(copy.title, "hostveil");
        assert!(copy.status.contains("No scan target selected yet"));
        assert!(copy.quit_hint.contains('q'));
        assert_eq!(copy.next_steps.len(), 3);
        assert!(
            copy.summary_lines
                .iter()
                .any(|line| line.contains("No Compose target loaded"))
        );
    }

    #[test]
    fn bootstrap_copy_reflects_loaded_compose_target() {
        let copy = bootstrap_copy(&ScanResult {
            metadata: ScanMetadata {
                compose_root: Some(PathBuf::from("/srv/demo")),
                compose_file: Some(PathBuf::from("/srv/demo/docker-compose.yml")),
                loaded_files: vec![
                    PathBuf::from("/srv/demo/docker-compose.yml"),
                    PathBuf::from("/srv/demo/docker-compose.override.yml"),
                ],
                service_count: 2,
                ..ScanMetadata::default()
            },
            ..ScanResult::default()
        });

        assert!(copy.status.contains("Loaded 2 service(s)"));
        assert!(
            copy.summary_lines
                .iter()
                .any(|line| line.contains("Compose file: /srv/demo/docker-compose.yml"))
        );
    }
}
