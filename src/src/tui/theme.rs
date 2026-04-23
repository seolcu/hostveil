use ratatui::style::{Color, Style};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThemePreset {
    Ansi,
    Catppuccin,
    Nord,
    TokyoNight,
    Gruvbox,
    Dracula,
    Monokai,
}

impl ThemePreset {
    pub const ALL: [Self; 7] = [
        Self::Ansi,
        Self::Catppuccin,
        Self::Nord,
        Self::TokyoNight,
        Self::Gruvbox,
        Self::Dracula,
        Self::Monokai,
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
            Self::Monokai => Self::Ansi,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Theme {
    pub preset: ThemePreset,
    pub base: Style,
    pub surface: Style,
    pub border: Style,
    pub title: Style,
    pub muted: Style,
    pub highlight: Style,
    pub status_bar: Style,
    pub accent: Color,
    pub crit: Color,
    pub high: Color,
    pub med: Color,
    pub low: Color,
    pub safe: Color,
    pub guided: Color,
    pub manual: Color,
}

impl Theme {
    pub const fn preset(preset: ThemePreset) -> Self {
        match preset {
            ThemePreset::Ansi => Self::ansi(),
            ThemePreset::Catppuccin => Self::catppuccin(),
            ThemePreset::Nord => Self::nord(),
            ThemePreset::TokyoNight => Self::tokyo_night(),
            ThemePreset::Gruvbox => Self::gruvbox(),
            ThemePreset::Dracula => Self::dracula(),
            ThemePreset::Monokai => Self::monokai(),
        }
    }

    const fn ansi() -> Self {
        Self {
            preset: ThemePreset::Ansi,
            base: Style::new().fg(Color::Reset),
            surface: Style::new().fg(Color::Reset),
            border: Style::new().fg(Color::DarkGray),
            title: Style::new().fg(Color::Cyan),
            muted: Style::new().fg(Color::Gray),
            highlight: Style::new().bg(Color::DarkGray),
            status_bar: Style::new().fg(Color::Gray),
            accent: Color::Cyan,
            crit: Color::LightRed,
            high: Color::Yellow,
            med: Color::LightYellow,
            low: Color::LightGreen,
            safe: Color::Green,
            guided: Color::Yellow,
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
            border: Style::new().fg(Color::Rgb(88, 91, 112)),
            title: Style::new().fg(Color::Rgb(137, 180, 250)),
            muted: Style::new().fg(Color::Rgb(127, 132, 156)),
            highlight: Style::new()
                .fg(Color::Rgb(205, 214, 244))
                .bg(Color::Rgb(49, 50, 68)),
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
            border: Style::new().fg(Color::Rgb(76, 86, 106)),
            title: Style::new().fg(Color::Rgb(136, 192, 208)),
            muted: Style::new().fg(Color::Rgb(143, 188, 187)),
            highlight: Style::new()
                .fg(Color::Rgb(229, 233, 240))
                .bg(Color::Rgb(59, 66, 82)),
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
            border: Style::new().fg(Color::Rgb(68, 76, 113)),
            title: Style::new().fg(Color::Rgb(122, 162, 247)),
            muted: Style::new().fg(Color::Rgb(125, 135, 185)),
            highlight: Style::new()
                .fg(Color::Rgb(192, 202, 245))
                .bg(Color::Rgb(41, 46, 66)),
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
            border: Style::new().fg(Color::Rgb(102, 92, 84)),
            title: Style::new().fg(Color::Rgb(131, 165, 152)),
            muted: Style::new().fg(Color::Rgb(168, 153, 132)),
            highlight: Style::new()
                .fg(Color::Rgb(251, 241, 199))
                .bg(Color::Rgb(60, 56, 54)),
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
            border: Style::new().fg(Color::Rgb(98, 114, 164)),
            title: Style::new().fg(Color::Rgb(139, 233, 253)),
            muted: Style::new().fg(Color::Rgb(98, 114, 164)),
            highlight: Style::new()
                .fg(Color::Rgb(248, 248, 242))
                .bg(Color::Rgb(68, 71, 90)),
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
            border: Style::new().fg(Color::Rgb(117, 113, 94)),
            title: Style::new().fg(Color::Rgb(102, 217, 239)),
            muted: Style::new().fg(Color::Rgb(117, 113, 94)),
            highlight: Style::new()
                .fg(Color::Rgb(248, 248, 242))
                .bg(Color::Rgb(73, 72, 62)),
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
            manual: Color::Rgb(102, 217, 239),
        }
    }
}
