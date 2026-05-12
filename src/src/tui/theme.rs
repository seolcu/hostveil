use ratatui::style::{Color, Style};
use ratatui::widgets::Borders;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ThemePreset {
    Ansi,
    Catppuccin,
    Nord,
    TokyoNight,
    Gruvbox,
    Dracula,
    Monokai,
    Light,
    SolarizedLight,
    System,
}

impl ThemePreset {
    pub const ALL: [Self; 10] = [
        Self::Ansi,
        Self::Catppuccin,
        Self::Nord,
        Self::TokyoNight,
        Self::Gruvbox,
        Self::Dracula,
        Self::Monokai,
        Self::Light,
        Self::SolarizedLight,
        Self::System,
    ];

    pub const fn as_key(self) -> &'static str {
        match self {
            Self::Ansi => "ansi",
            Self::Catppuccin => "catppuccin",
            Self::Nord => "nord",
            Self::TokyoNight => "tokyo_night",
            Self::Gruvbox => "gruvbox",
            Self::Dracula => "dracula",
            Self::Monokai => "monokai",
            Self::Light => "light",
            Self::SolarizedLight => "solarized_light",
            Self::System => "system",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Ansi => "ANSI",
            Self::Catppuccin => "Catppuccin",
            Self::Nord => "Nord",
            Self::TokyoNight => "Tokyo Night",
            Self::Gruvbox => "Gruvbox",
            Self::Dracula => "Dracula",
            Self::Monokai => "Monokai",
            Self::Light => "Light",
            Self::SolarizedLight => "Solarized Light",
            Self::System => "System",
        }
    }

    pub fn from_key(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|preset| preset.as_key() == value.trim().to_ascii_lowercase())
    }

    pub const fn next(self) -> Self {
        match self {
            Self::Ansi => Self::Catppuccin,
            Self::Catppuccin => Self::Nord,
            Self::Nord => Self::TokyoNight,
            Self::TokyoNight => Self::Gruvbox,
            Self::Gruvbox => Self::Dracula,
            Self::Dracula => Self::Monokai,
            Self::Monokai => Self::Light,
            Self::Light => Self::SolarizedLight,
            Self::SolarizedLight => Self::System,
            Self::System => Self::Ansi,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Theme {
    pub preset: ThemePreset,
    pub base: Style,
    pub surface: Style,
    pub panel_bg: Style,
    pub panel_bg_alt: Style,
    pub focus_bg: Style,
    pub border: Style,
    pub title: Style,
    pub muted: Style,
    pub highlight: Style,
    pub tab_active: Style,
    pub tab_inactive: Style,
    pub status_bar: Style,
    pub accent: Color,
    pub crit: Color,
    pub high: Color,
    pub med: Color,
    pub low: Color,
    pub safe: Color,
    pub guided: Color,
    pub manual: Color,
    pub borders_enabled: bool,
    pub modal_bg: Style,
    pub modal_border: Style,
}

impl Theme {
    pub fn preset(preset: ThemePreset) -> Self {
        match preset {
            ThemePreset::Ansi => Self::ansi(),
            ThemePreset::Catppuccin => Self::catppuccin(),
            ThemePreset::Nord => Self::nord(),
            ThemePreset::TokyoNight => Self::tokyo_night(),
            ThemePreset::Gruvbox => Self::gruvbox(),
            ThemePreset::Dracula => Self::dracula(),
            ThemePreset::Monokai => Self::monokai(),
            ThemePreset::Light => Self::light(),
            ThemePreset::SolarizedLight => Self::solarized_light(),
            ThemePreset::System => Self::system(),
        }
    }

    fn system() -> Self {
        let bg_is_light = std::env::var("COLORFGBG")
            .ok()
            .and_then(|value| value.split(';').nth(1).map(str::to_owned))
            .and_then(|bg| bg.parse::<u8>().ok())
            .is_some_and(|bg| bg >= 7);

        if bg_is_light {
            Self::light()
        } else {
            Self::tokyo_night()
        }
    }

    const fn ansi() -> Self {
        Self {
            preset: ThemePreset::Ansi,
            base: Style::new().fg(Color::Reset),
            surface: Style::new().fg(Color::Reset),
            panel_bg: Style::new().bg(Color::Rgb(38, 38, 38)),
            panel_bg_alt: Style::new().bg(Color::Rgb(34, 34, 34)),
            focus_bg: Style::new().bg(Color::Rgb(50, 50, 50)),
            border: Style::new().fg(Color::DarkGray),
            title: Style::new().fg(Color::Cyan),
            muted: Style::new().fg(Color::Gray),
            highlight: Style::new().bg(Color::DarkGray),
            tab_active: Style::new()
                .fg(Color::Cyan)
                .add_modifier(ratatui::style::Modifier::BOLD),
            tab_inactive: Style::new().fg(Color::Gray),
            status_bar: Style::new().fg(Color::Gray),
            accent: Color::Cyan,
            crit: Color::LightRed,
            high: Color::Yellow,
            med: Color::LightYellow,
            low: Color::LightGreen,
            safe: Color::Green,
            guided: Color::Yellow,
            borders_enabled: false,
            modal_bg: Style::new().bg(Color::Rgb(46, 46, 47)),
            modal_border: Style::new().fg(Color::Cyan),
            manual: Color::LightBlue,
        }
    }

    const fn catppuccin() -> Self {
        Self {
            preset: ThemePreset::Catppuccin,
            base: Style::new().fg(Color::Rgb(205, 214, 244)),
            surface: Style::new()
                .fg(Color::Rgb(205, 214, 244))
                .bg(Color::Rgb(30, 30, 46)),
            panel_bg: Style::new().bg(Color::Rgb(36, 36, 54)),
            panel_bg_alt: Style::new().bg(Color::Rgb(32, 32, 50)),
            focus_bg: Style::new().bg(Color::Rgb(42, 42, 62)),
            border: Style::new().fg(Color::Rgb(88, 91, 112)),
            title: Style::new().fg(Color::Rgb(137, 180, 250)),
            muted: Style::new().fg(Color::Rgb(127, 132, 156)),
            highlight: Style::new()
                .fg(Color::Rgb(205, 214, 244))
                .bg(Color::Rgb(70, 71, 95)),
            tab_active: Style::new()
                .fg(Color::Rgb(137, 180, 250))
                .add_modifier(ratatui::style::Modifier::BOLD),
            tab_inactive: Style::new().fg(Color::Rgb(127, 132, 156)),
            status_bar: Style::new()
                .fg(Color::Rgb(147, 153, 178))
                .bg(Color::Rgb(24, 24, 37)),
            accent: Color::Rgb(137, 180, 250),
            crit: Color::Rgb(243, 139, 168),
            high: Color::Rgb(250, 179, 135),
            med: Color::Rgb(249, 226, 175),
            low: Color::Rgb(166, 227, 161),
            safe: Color::Rgb(166, 227, 161),
            guided: Color::Rgb(249, 226, 175),
            borders_enabled: false,
            modal_bg: Style::new().bg(Color::Rgb(34, 34, 50)),
            modal_border: Style::new().fg(Color::Rgb(137, 180, 250)),
            manual: Color::Rgb(137, 180, 250),
        }
    }

    const fn nord() -> Self {
        Self {
            preset: ThemePreset::Nord,
            base: Style::new().fg(Color::Rgb(216, 222, 233)),
            surface: Style::new()
                .fg(Color::Rgb(216, 222, 233))
                .bg(Color::Rgb(43, 48, 59)),
            panel_bg: Style::new().bg(Color::Rgb(50, 56, 70)),
            panel_bg_alt: Style::new().bg(Color::Rgb(46, 52, 64)),
            focus_bg: Style::new().bg(Color::Rgb(58, 64, 80)),
            border: Style::new().fg(Color::Rgb(76, 86, 106)),
            title: Style::new().fg(Color::Rgb(136, 192, 208)),
            muted: Style::new().fg(Color::Rgb(143, 188, 187)),
            highlight: Style::new()
                .fg(Color::Rgb(229, 233, 240))
                .bg(Color::Rgb(82, 91, 110)),
            tab_active: Style::new()
                .fg(Color::Rgb(136, 192, 208))
                .add_modifier(ratatui::style::Modifier::BOLD),
            tab_inactive: Style::new().fg(Color::Rgb(143, 188, 187)),
            status_bar: Style::new()
                .fg(Color::Rgb(129, 161, 193))
                .bg(Color::Rgb(46, 52, 64)),
            accent: Color::Rgb(136, 192, 208),
            crit: Color::Rgb(191, 97, 106),
            high: Color::Rgb(208, 135, 112),
            med: Color::Rgb(235, 203, 139),
            low: Color::Rgb(163, 190, 140),
            safe: Color::Rgb(163, 190, 140),
            guided: Color::Rgb(235, 203, 139),
            borders_enabled: false,
            modal_bg: Style::new().bg(Color::Rgb(47, 52, 63)),
            modal_border: Style::new().fg(Color::Rgb(136, 192, 208)),
            manual: Color::Rgb(129, 161, 193),
        }
    }

    const fn tokyo_night() -> Self {
        Self {
            preset: ThemePreset::TokyoNight,
            base: Style::new().fg(Color::Rgb(169, 177, 214)),
            surface: Style::new()
                .fg(Color::Rgb(169, 177, 214))
                .bg(Color::Rgb(22, 22, 30)),
            panel_bg: Style::new().bg(Color::Rgb(28, 28, 38)),
            panel_bg_alt: Style::new().bg(Color::Rgb(25, 25, 34)),
            focus_bg: Style::new().bg(Color::Rgb(36, 36, 50)),
            border: Style::new().fg(Color::Rgb(68, 76, 113)),
            title: Style::new().fg(Color::Rgb(122, 162, 247)),
            muted: Style::new().fg(Color::Rgb(125, 135, 185)),
            highlight: Style::new()
                .fg(Color::Rgb(192, 202, 245))
                .bg(Color::Rgb(65, 72, 100)),
            tab_active: Style::new()
                .fg(Color::Rgb(122, 162, 247))
                .add_modifier(ratatui::style::Modifier::BOLD),
            tab_inactive: Style::new().fg(Color::Rgb(125, 135, 185)),
            status_bar: Style::new()
                .fg(Color::Rgb(125, 135, 185))
                .bg(Color::Rgb(26, 27, 38)),
            accent: Color::Rgb(122, 162, 247),
            crit: Color::Rgb(247, 118, 142),
            high: Color::Rgb(255, 158, 100),
            med: Color::Rgb(224, 175, 104),
            low: Color::Rgb(158, 206, 106),
            safe: Color::Rgb(158, 206, 106),
            guided: Color::Rgb(224, 175, 104),
            borders_enabled: false,
            modal_bg: Style::new().bg(Color::Rgb(26, 26, 34)),
            modal_border: Style::new().fg(Color::Rgb(122, 162, 247)),
            manual: Color::Rgb(122, 162, 247),
        }
    }

    const fn gruvbox() -> Self {
        Self {
            preset: ThemePreset::Gruvbox,
            base: Style::new().fg(Color::Rgb(235, 219, 178)),
            surface: Style::new()
                .fg(Color::Rgb(235, 219, 178))
                .bg(Color::Rgb(29, 32, 33)),
            panel_bg: Style::new().bg(Color::Rgb(36, 40, 41)),
            panel_bg_alt: Style::new().bg(Color::Rgb(32, 36, 37)),
            focus_bg: Style::new().bg(Color::Rgb(44, 48, 49)),
            border: Style::new().fg(Color::Rgb(102, 92, 84)),
            title: Style::new().fg(Color::Rgb(131, 165, 152)),
            muted: Style::new().fg(Color::Rgb(168, 153, 132)),
            highlight: Style::new()
                .fg(Color::Rgb(251, 241, 199))
                .bg(Color::Rgb(85, 80, 77)),
            tab_active: Style::new()
                .fg(Color::Rgb(131, 165, 152))
                .add_modifier(ratatui::style::Modifier::BOLD),
            tab_inactive: Style::new().fg(Color::Rgb(168, 153, 132)),
            status_bar: Style::new()
                .fg(Color::Rgb(168, 153, 132))
                .bg(Color::Rgb(40, 40, 40)),
            accent: Color::Rgb(131, 165, 152),
            crit: Color::Rgb(204, 36, 29),
            high: Color::Rgb(214, 93, 14),
            med: Color::Rgb(215, 153, 33),
            low: Color::Rgb(152, 151, 26),
            safe: Color::Rgb(152, 151, 26),
            guided: Color::Rgb(215, 153, 33),
            borders_enabled: false,
            modal_bg: Style::new().bg(Color::Rgb(33, 36, 37)),
            modal_border: Style::new().fg(Color::Rgb(131, 165, 152)),
            manual: Color::Rgb(69, 133, 136),
        }
    }

    const fn dracula() -> Self {
        Self {
            preset: ThemePreset::Dracula,
            base: Style::new().fg(Color::Rgb(248, 248, 242)),
            surface: Style::new()
                .fg(Color::Rgb(248, 248, 242))
                .bg(Color::Rgb(40, 42, 54)),
            panel_bg: Style::new().bg(Color::Rgb(46, 48, 62)),
            panel_bg_alt: Style::new().bg(Color::Rgb(43, 45, 58)),
            focus_bg: Style::new().bg(Color::Rgb(54, 56, 72)),
            border: Style::new().fg(Color::Rgb(98, 114, 164)),
            title: Style::new().fg(Color::Rgb(139, 233, 253)),
            muted: Style::new().fg(Color::Rgb(98, 114, 164)),
            highlight: Style::new()
                .fg(Color::Rgb(248, 248, 242))
                .bg(Color::Rgb(90, 93, 115)),
            tab_active: Style::new()
                .fg(Color::Rgb(139, 233, 253))
                .add_modifier(ratatui::style::Modifier::BOLD),
            tab_inactive: Style::new().fg(Color::Rgb(98, 114, 164)),
            status_bar: Style::new()
                .fg(Color::Rgb(248, 248, 242))
                .bg(Color::Rgb(33, 34, 44)),
            accent: Color::Rgb(189, 147, 249),
            crit: Color::Rgb(255, 85, 85),
            high: Color::Rgb(255, 184, 108),
            med: Color::Rgb(241, 250, 140),
            low: Color::Rgb(80, 250, 123),
            safe: Color::Rgb(80, 250, 123),
            guided: Color::Rgb(241, 250, 140),
            borders_enabled: false,
            modal_bg: Style::new().bg(Color::Rgb(44, 46, 58)),
            modal_border: Style::new().fg(Color::Rgb(139, 233, 253)),
            manual: Color::Rgb(139, 233, 253),
        }
    }

    const fn monokai() -> Self {
        Self {
            preset: ThemePreset::Monokai,
            base: Style::new().fg(Color::Rgb(248, 248, 242)),
            surface: Style::new()
                .fg(Color::Rgb(248, 248, 242))
                .bg(Color::Rgb(39, 40, 34)),
            panel_bg: Style::new().bg(Color::Rgb(45, 46, 40)),
            panel_bg_alt: Style::new().bg(Color::Rgb(42, 43, 37)),
            focus_bg: Style::new().bg(Color::Rgb(52, 53, 46)),
            border: Style::new().fg(Color::Rgb(117, 113, 94)),
            title: Style::new().fg(Color::Rgb(102, 217, 239)),
            muted: Style::new().fg(Color::Rgb(117, 113, 94)),
            highlight: Style::new()
                .fg(Color::Rgb(248, 248, 242))
                .bg(Color::Rgb(95, 94, 82)),
            tab_active: Style::new()
                .fg(Color::Rgb(102, 217, 239))
                .add_modifier(ratatui::style::Modifier::BOLD),
            tab_inactive: Style::new().fg(Color::Rgb(117, 113, 94)),
            status_bar: Style::new()
                .fg(Color::Rgb(248, 248, 242))
                .bg(Color::Rgb(30, 31, 28)),
            accent: Color::Rgb(253, 151, 31),
            crit: Color::Rgb(249, 38, 114),
            high: Color::Rgb(253, 151, 31),
            med: Color::Rgb(230, 219, 116),
            low: Color::Rgb(166, 226, 46),
            safe: Color::Rgb(166, 226, 46),
            guided: Color::Rgb(230, 219, 116),
            borders_enabled: false,
            modal_bg: Style::new().bg(Color::Rgb(43, 44, 38)),
            modal_border: Style::new().fg(Color::Rgb(102, 217, 239)),
            manual: Color::Rgb(102, 217, 239),
        }
    }

    const fn light() -> Self {
        Self {
            preset: ThemePreset::Light,
            base: Style::new().fg(Color::Rgb(51, 51, 51)),
            surface: Style::new()
                .fg(Color::Rgb(51, 51, 51))
                .bg(Color::Rgb(250, 250, 250)),
            panel_bg: Style::new().bg(Color::Rgb(245, 245, 245)),
            panel_bg_alt: Style::new().bg(Color::Rgb(240, 240, 240)),
            focus_bg: Style::new().bg(Color::Rgb(230, 230, 230)),
            border: Style::new().fg(Color::Rgb(180, 180, 180)),
            title: Style::new().fg(Color::Rgb(0, 102, 204)),
            muted: Style::new().fg(Color::Rgb(136, 136, 136)),
            highlight: Style::new()
                .fg(Color::Rgb(51, 51, 51))
                .bg(Color::Rgb(200, 200, 200)),
            tab_active: Style::new()
                .fg(Color::Rgb(0, 102, 204))
                .add_modifier(ratatui::style::Modifier::BOLD),
            tab_inactive: Style::new().fg(Color::Rgb(136, 136, 136)),
            status_bar: Style::new()
                .fg(Color::Rgb(102, 102, 102))
                .bg(Color::Rgb(240, 240, 240)),
            accent: Color::Rgb(0, 102, 204),
            crit: Color::Rgb(204, 0, 0),
            high: Color::Rgb(230, 126, 34),
            med: Color::Rgb(241, 196, 15),
            low: Color::Rgb(39, 174, 96),
            safe: Color::Rgb(39, 174, 96),
            guided: Color::Rgb(241, 196, 15),
            borders_enabled: false,
            modal_bg: Style::new().bg(Color::Rgb(235, 235, 235)),
            modal_border: Style::new().fg(Color::Rgb(0, 102, 204)),
            manual: Color::Rgb(0, 102, 204),
        }
    }

    const fn solarized_light() -> Self {
        Self {
            preset: ThemePreset::SolarizedLight,
            base: Style::new().fg(Color::Rgb(101, 123, 131)),
            surface: Style::new()
                .fg(Color::Rgb(101, 123, 131))
                .bg(Color::Rgb(253, 246, 227)),
            panel_bg: Style::new().bg(Color::Rgb(248, 240, 218)),
            panel_bg_alt: Style::new().bg(Color::Rgb(243, 235, 210)),
            focus_bg: Style::new().bg(Color::Rgb(235, 228, 200)),
            border: Style::new().fg(Color::Rgb(147, 161, 161)),
            title: Style::new().fg(Color::Rgb(38, 139, 210)),
            muted: Style::new().fg(Color::Rgb(147, 161, 161)),
            highlight: Style::new()
                .fg(Color::Rgb(101, 123, 131))
                .bg(Color::Rgb(220, 214, 195)),
            tab_active: Style::new()
                .fg(Color::Rgb(38, 139, 210))
                .add_modifier(ratatui::style::Modifier::BOLD),
            tab_inactive: Style::new().fg(Color::Rgb(147, 161, 161)),
            status_bar: Style::new()
                .fg(Color::Rgb(131, 148, 150))
                .bg(Color::Rgb(245, 238, 220)),
            accent: Color::Rgb(38, 139, 210),
            crit: Color::Rgb(220, 50, 47),
            high: Color::Rgb(203, 75, 22),
            med: Color::Rgb(181, 137, 0),
            low: Color::Rgb(133, 153, 0),
            safe: Color::Rgb(133, 153, 0),
            guided: Color::Rgb(181, 137, 0),
            borders_enabled: false,
            modal_bg: Style::new().bg(Color::Rgb(238, 232, 218)),
            modal_border: Style::new().fg(Color::Rgb(38, 139, 210)),
            manual: Color::Rgb(38, 139, 210),
        }
    }
}

pub fn panel_borders(theme: &Theme) -> Borders {
    if theme.borders_enabled {
        Borders::ALL
    } else {
        Borders::NONE
    }
}

#[cfg(test)]
mod tests {
    use super::{Theme, ThemePreset};
    use ratatui::style::Color;

    #[test]
    fn all_presets_have_distinct_keys() {
        let mut keys = std::collections::HashSet::new();
        for preset in ThemePreset::ALL {
            let key = preset.as_key();
            assert!(keys.insert(key), "duplicate theme key: {key}");
        }
        assert_eq!(keys.len(), ThemePreset::ALL.len());
    }

    #[test]
    fn all_presets_have_labels() {
        for preset in ThemePreset::ALL {
            let label = preset.label();
            assert!(!label.is_empty(), "theme preset {preset:?} has empty label");
        }
    }

    #[test]
    fn all_presets_can_be_constructed() {
        for preset in ThemePreset::ALL {
            let theme = Theme::preset(preset);
            if preset != ThemePreset::System {
                assert_eq!(theme.preset, preset);
            }
            assert!(!matches!(theme.crit, Color::Reset));
        }
    }

    #[test]
    fn preset_roundtrip_from_key() {
        for preset in ThemePreset::ALL {
            let key = preset.as_key();
            let recovered = ThemePreset::from_key(key);
            assert_eq!(
                recovered,
                Some(preset),
                "preset {preset:?} should roundtrip through key '{key}'"
            );
        }
    }

    #[test]
    fn next_cycles_through_all_presets() {
        let start = ThemePreset::Ansi;
        let mut current = start;
        let mut visited = std::collections::HashSet::new();
        loop {
            visited.insert(current);
            current = current.next();
            if current == start {
                break;
            }
        }
        assert_eq!(
            visited.len(),
            ThemePreset::ALL.len(),
            "next() should cycle through all presets"
        );
    }

    #[test]
    fn theme_from_key_is_case_insensitive() {
        assert_eq!(ThemePreset::from_key("ANSI"), Some(ThemePreset::Ansi));
        assert_eq!(
            ThemePreset::from_key("Tokyo_Night"),
            Some(ThemePreset::TokyoNight)
        );
        assert_eq!(ThemePreset::from_key("GRUVBOX"), Some(ThemePreset::Gruvbox));
    }

    #[test]
    fn theme_from_key_returns_none_for_unknown() {
        assert_eq!(ThemePreset::from_key("unknown_theme"), None);
        assert_eq!(ThemePreset::from_key(""), None);
    }

    #[test]
    fn each_preset_defines_all_colors() {
        for preset in ThemePreset::ALL {
            let theme = Theme::preset(preset);
            assert!(!matches!(theme.crit, Color::Reset));
            assert!(!matches!(theme.high, Color::Reset));
            assert!(!matches!(theme.med, Color::Reset));
            assert!(!matches!(theme.low, Color::Reset));
            assert!(!matches!(theme.safe, Color::Reset));
            assert!(!matches!(theme.manual, Color::Reset));
        }
    }

    #[test]
    fn system_preset_does_not_panic() {
        let theme = Theme::preset(ThemePreset::System);
        assert_ne!(theme.preset, ThemePreset::System);
        assert!(!matches!(theme.crit, Color::Reset));
    }

    #[test]
    fn all_presets_define_panel_backgrounds() {
        for preset in ThemePreset::ALL {
            let theme = Theme::preset(preset);
            assert!(theme.panel_bg.bg.is_some());
            assert!(theme.panel_bg_alt.bg.is_some());
            assert!(theme.focus_bg.bg.is_some());
        }
    }

    #[test]
    fn all_presets_define_tab_styles() {
        for preset in ThemePreset::ALL {
            let theme = Theme::preset(preset);
            assert!(theme.tab_active.fg.is_some());
            assert!(theme.tab_inactive.fg.is_some());
        }
    }

    #[test]
    fn panel_backgrounds_are_distinct_from_surface() {
        for preset in ThemePreset::ALL {
            let theme = Theme::preset(preset);
            if let (Some(surf_bg), Some(panel_bg)) = (theme.surface.bg, theme.panel_bg.bg) {
                assert_ne!(surf_bg, panel_bg);
            }
        }
    }
}
