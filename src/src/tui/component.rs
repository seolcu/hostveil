use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    text::{Span, Text},
    widgets::{Block, Padding, Paragraph, Wrap},
};

use super::theme::{Theme, panel_borders};

pub trait Component {
    fn render(&self, frame: &mut Frame, area: Rect, theme: &Theme);
}

pub struct Panel {
    pub title: String,
    pub content: Text<'static>,
    pub scroll: usize,
    pub is_focused: bool,
    pub is_alt_bg: bool,
}

impl Panel {
    pub fn new(title: String, content: Text<'static>) -> Self {
        Self {
            title,
            content,
            scroll: 0,
            is_focused: false,
            is_alt_bg: false,
        }
    }

    pub fn with_scroll(mut self, scroll: usize) -> Self {
        self.scroll = scroll;
        self
    }

    pub fn focused(mut self, is_focused: bool) -> Self {
        self.is_focused = is_focused;
        self
    }

    pub fn alt_bg(mut self, is_alt_bg: bool) -> Self {
        self.is_alt_bg = is_alt_bg;
        self
    }

    fn bg_style(&self, theme: &Theme) -> Style {
        if self.is_focused {
            theme.focus_bg
        } else if self.is_alt_bg {
            theme.panel_bg_alt
        } else {
            theme.panel_bg
        }
    }
}

impl Component for Panel {
    fn render(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let bg_style = self.bg_style(theme);
        let title_style = if self.is_focused {
            theme.title
        } else {
            theme.muted
        };

        frame.render_widget(
            Paragraph::new(self.content.clone())
                .style(bg_style)
                .wrap(Wrap { trim: false })
                .scroll((self.scroll as u16, 0))
                .block(
                    Block::default()
                        .title(Span::styled(&self.title, title_style))
                        .borders(panel_borders(theme))
                        .border_style(theme.border)
                        .style(bg_style)
                        .padding(Padding::horizontal(1)),
                ),
            area,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::super::theme::{Theme, ThemePreset, panel_borders};
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::text::Text;
    use ratatui::widgets::Borders;

    fn test_theme() -> Theme {
        Theme::preset(ThemePreset::TokyoNight)
    }

    #[test]
    fn panel_new_defaults() {
        let panel = Panel::new("Test".to_string(), Text::raw("content"));
        assert_eq!(panel.scroll, 0);
        assert!(!panel.is_focused);
        assert!(!panel.is_alt_bg);
        assert_eq!(panel.title, "Test");
    }

    #[test]
    fn panel_focused_sets_focus() {
        let panel = Panel::new("T".to_string(), Text::raw("c")).focused(true);
        assert!(panel.is_focused);
    }

    #[test]
    fn panel_bg_style_focused() {
        let theme = test_theme();
        let panel = Panel::new("T".to_string(), Text::raw("c")).focused(true);
        let bg = panel.bg_style(&theme);
        assert_eq!(bg, theme.focus_bg);
    }

    #[test]
    fn panel_bg_style_alt() {
        let theme = test_theme();
        let panel = Panel::new("T".to_string(), Text::raw("c")).alt_bg(true);
        let bg = panel.bg_style(&theme);
        assert_eq!(bg, theme.panel_bg_alt);
    }

    #[test]
    fn panel_bg_style_default() {
        let theme = test_theme();
        let panel = Panel::new("T".to_string(), Text::raw("c"));
        let bg = panel.bg_style(&theme);
        assert_eq!(bg, theme.panel_bg);
    }

    #[test]
    fn panel_renders_borderless_when_default() {
        let theme = test_theme();
        let panel = Panel::new("Title".to_string(), Text::raw("hello world"));
        let mut terminal = Terminal::new(TestBackend::new(40, 10)).expect("terminal");
        terminal
            .draw(|frame| panel.render(frame, frame.area(), &theme))
            .expect("render");
        let content = terminal.backend().buffer();
        // borderless → no box-drawing characters
        let cell = &content[(0, 0)];
        assert_ne!(cell.symbol(), "┌", "borderless should not show corner");
    }

    #[test]
    fn panel_renders_borders_when_enabled() {
        let mut theme = test_theme();
        theme.borders_enabled = true;
        let panel = Panel::new("Title".to_string(), Text::raw("hello world"));
        let mut terminal = Terminal::new(TestBackend::new(40, 10)).expect("terminal");
        terminal
            .draw(|frame| panel.render(frame, frame.area(), &theme))
            .expect("render");
        let content = terminal.backend().buffer();
        let cell = &content[(0, 0)];
        assert_eq!(cell.symbol(), "┌", "bordered should show corner");
    }

    #[test]
    fn panel_renders_without_panic() {
        let theme = test_theme();
        let panel = Panel::new("T".to_string(), Text::raw("hello"));
        let mut terminal = Terminal::new(TestBackend::new(40, 10)).expect("terminal");
        terminal
            .draw(|frame| panel.render(frame, frame.area(), &theme))
            .expect("panel render should not panic");
        // If we reach here without panicking, rendering succeeded
    }

    #[test]
    fn panel_default_borders_disabled() {
        let theme = test_theme();
        assert_eq!(panel_borders(&theme), Borders::NONE);
    }

    #[test]
    fn panel_borders_enabled_returns_all() {
        let mut theme = test_theme();
        theme.borders_enabled = true;
        assert_eq!(panel_borders(&theme), Borders::ALL);
    }
}
