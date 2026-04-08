use std::io;

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::text::{Line, Text};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::fix::FixPlan;

#[derive(Debug, Clone, PartialEq, Eq)]
struct FixReviewState {
    scroll: u16,
}

pub fn run_fix_review(plan: &FixPlan) -> io::Result<bool> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let mut state = FixReviewState { scroll: 0 };

    let result = run_event_loop(&mut terminal, plan, &mut state);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    plan: &FixPlan,
    state: &mut FixReviewState,
) -> io::Result<bool> {
    loop {
        terminal.draw(|frame| render(frame, plan, state))?;

        match event::read()? {
            Event::Key(key) if key.kind == KeyEventKind::Press => match key.code {
                KeyCode::Char('q') | KeyCode::Esc => return Ok(false),
                KeyCode::Char('y') | KeyCode::Enter => return Ok(true),
                KeyCode::Down | KeyCode::Char('j') => state.scroll = state.scroll.saturating_add(1),
                KeyCode::Up | KeyCode::Char('k') => state.scroll = state.scroll.saturating_sub(1),
                KeyCode::PageDown => state.scroll = state.scroll.saturating_add(8),
                KeyCode::PageUp => state.scroll = state.scroll.saturating_sub(8),
                _ => {}
            },
            Event::Resize(_, _) => {}
            _ => {}
        }
    }
}

fn render(frame: &mut ratatui::Frame<'_>, plan: &FixPlan, state: &mut FixReviewState) {
    let diff_lines = plan.diff_preview.lines().count();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(9),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(frame.area());

    let mut summary = Vec::<Line>::new();
    summary.push(Line::from(
        t!(
            "app.fix.file",
            path = plan.compose_file.display().to_string()
        )
        .into_owned(),
    ));
    if !plan.safe_applied.is_empty() {
        summary.push(Line::from(
            t!("app.fix.safe_plan", count = plan.safe_applied.len()).into_owned(),
        ));
        for proposal in &plan.safe_applied {
            summary.push(Line::from(format!("- {}", proposal.summary)));
        }
    }
    if !plan.guided_applied.is_empty() {
        summary.push(Line::from(
            t!("app.fix.guided_plan", count = plan.guided_applied.len()).into_owned(),
        ));
        for proposal in &plan.guided_applied {
            summary.push(Line::from(format!("- {}", proposal.summary)));
        }
    }

    let summary_widget = Paragraph::new(Text::from(summary))
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .title(t!("app.panel.fix_review").into_owned())
                .borders(Borders::ALL),
        );
    frame.render_widget(summary_widget, chunks[0]);

    let diff_text = Text::from(
        plan.diff_preview
            .lines()
            .map(|line| Line::from(line.to_owned()))
            .collect::<Vec<_>>(),
    );

    let diff_height = chunks[1].height.saturating_sub(2) as usize;
    let max_scroll = diff_lines.saturating_sub(diff_height);
    state.scroll = state.scroll.min(max_scroll.min(u16::MAX as usize) as u16);

    let diff_widget = Paragraph::new(diff_text)
        .scroll((state.scroll, 0))
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .title(t!("app.panel.fix_diff").into_owned())
                .borders(Borders::ALL),
        );
    frame.render_widget(diff_widget, chunks[1]);

    let hints = vec![
        Line::from(t!("app.hint.fix_review_scroll").into_owned()),
        Line::from(t!("app.hint.fix_review_apply").into_owned()),
        Line::from(t!("app.hint.fix_review_cancel").into_owned()),
    ];
    let hints_widget = Paragraph::new(Text::from(hints))
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(t!("app.panel.hints").into_owned()),
        );
    frame.render_widget(hints_widget, chunks[2]);
}
