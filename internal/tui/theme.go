package tui

// Theme holds lipgloss color hex values for the terminal UI.
type Theme struct {
	Background string
	SurfaceAlt string
	Border     string
	Text       string
	TextMuted  string
	Critical   string
	High       string
	Medium     string
	Low        string
	Accent     string
	Success    string
}

const (
	ThemeDefault    = "default"
	ThemeTokyoNight = "tokyo-night"
	ThemeCatppuccin = "catppuccin"
	ThemeNord       = "nord"
	ThemeDracula    = "dracula"
	ThemeGruvbox    = "gruvbox"
	ThemeOneDark    = "one-dark"
	ThemeSolarized  = "solarized"
	ThemeMonokai    = "monokai"
	ThemeEverforest = "everforest"
	ThemeRosePine   = "rose-pine"
	ThemeKanagawa   = "kanagawa"
	ThemeGitHubDark = "github-dark"
	ThemeAyuDark    = "ayu-dark"
	ThemeNightOwl   = "night-owl"
)

type themeEntry struct {
	id    string
	label string
	theme Theme
}

var themeRegistry = []themeEntry{
	{
		id: ThemeDefault, label: "Default",
		theme: Theme{
			Background: "#090b12", SurfaceAlt: "#171c2b", Border: "#2f3a52",
			Text: "#e7ecf8", TextMuted: "#8390ad",
			Critical: "#ff5573", High: "#ff9868", Medium: "#f7c66b", Low: "#87d978",
			Accent: "#64c8ff", Success: "#87d978",
		},
	},
	{
		id: ThemeTokyoNight, label: "Tokyo Night",
		theme: Theme{
			Background: "#1a1b26", SurfaceAlt: "#24283b", Border: "#292e42",
			Text: "#c0caf5", TextMuted: "#565f89",
			Critical: "#f7768e", High: "#ff9e64", Medium: "#e0af68", Low: "#9ece6a",
			Accent: "#7aa2f7", Success: "#9ece6a",
		},
	},
	{
		id: ThemeCatppuccin, label: "Catppuccin",
		theme: Theme{
			Background: "#1e1e2e", SurfaceAlt: "#313244", Border: "#45475a",
			Text: "#cdd6f4", TextMuted: "#6c7086",
			Critical: "#f38ba8", High: "#fab387", Medium: "#f9e2af", Low: "#a6e3a1",
			Accent: "#89b4fa", Success: "#a6e3a1",
		},
	},
	{
		id: ThemeNord, label: "Nord",
		theme: Theme{
			Background: "#2e3440", SurfaceAlt: "#434c5e", Border: "#4c566a",
			Text: "#eceff4", TextMuted: "#616e88",
			Critical: "#bf616a", High: "#d08770", Medium: "#ebcb8b", Low: "#a3be8c",
			Accent: "#88c0d0", Success: "#a3be8c",
		},
	},
	{
		id: ThemeDracula, label: "Dracula",
		theme: Theme{
			Background: "#282a36", SurfaceAlt: "#44475a", Border: "#44475a",
			Text: "#f8f8f2", TextMuted: "#6272a4",
			Critical: "#ff5555", High: "#ffb86c", Medium: "#f1fa8c", Low: "#50fa7b",
			Accent: "#bd93f9", Success: "#50fa7b",
		},
	},
	{
		id: ThemeGruvbox, label: "Gruvbox",
		theme: Theme{
			Background: "#282828", SurfaceAlt: "#3c3836", Border: "#504945",
			Text: "#ebdbb2", TextMuted: "#928374",
			Critical: "#fb4934", High: "#fe8019", Medium: "#fabd2f", Low: "#b8bb26",
			Accent: "#83a598", Success: "#b8bb26",
		},
	},
	{
		id: ThemeOneDark, label: "One Dark",
		theme: Theme{
			Background: "#282c34", SurfaceAlt: "#2c313c", Border: "#3e4451",
			Text: "#abb2bf", TextMuted: "#5c6370",
			Critical: "#e06c75", High: "#d19a66", Medium: "#e5c07b", Low: "#98c379",
			Accent: "#61afef", Success: "#98c379",
		},
	},
	{
		id: ThemeSolarized, label: "Solarized Dark",
		theme: Theme{
			Background: "#002b36", SurfaceAlt: "#073642", Border: "#094352",
			Text: "#93a1a1", TextMuted: "#657b83",
			Critical: "#dc322f", High: "#cb4b16", Medium: "#b58900", Low: "#859900",
			Accent: "#268bd2", Success: "#859900",
		},
	},
	{
		id: ThemeMonokai, label: "Monokai",
		theme: Theme{
			Background: "#272822", SurfaceAlt: "#3e3d32", Border: "#49483e",
			Text: "#f8f8f2", TextMuted: "#75715e",
			Critical: "#f92672", High: "#fd971f", Medium: "#e6db74", Low: "#a6e22e",
			Accent: "#66d9ef", Success: "#a6e22e",
		},
	},
	{
		id: ThemeEverforest, label: "Everforest",
		theme: Theme{
			Background: "#2d353b", SurfaceAlt: "#3d484d", Border: "#475258",
			Text: "#d3c6aa", TextMuted: "#859289",
			Critical: "#e67e80", High: "#e69875", Medium: "#dbbc7f", Low: "#a7c080",
			Accent: "#7fbbb3", Success: "#a7c080",
		},
	},
	{
		id: ThemeRosePine, label: "Rosé Pine",
		theme: Theme{
			Background: "#191724", SurfaceAlt: "#26233a", Border: "#403d52",
			Text: "#e0def4", TextMuted: "#6e6a86",
			Critical: "#eb6f92", High: "#f6c177", Medium: "#e0c989", Low: "#9ccfd8",
			Accent: "#c4a7e7", Success: "#9ccfd8",
		},
	},
	{
		id: ThemeKanagawa, label: "Kanagawa",
		theme: Theme{
			Background: "#1f1f28", SurfaceAlt: "#2a2a37", Border: "#363646",
			Text: "#dcd7ba", TextMuted: "#727169",
			Critical: "#c34043", High: "#ffa066", Medium: "#e6c384", Low: "#76946a",
			Accent: "#7e9cd8", Success: "#76946a",
		},
	},
	{
		id: ThemeGitHubDark, label: "GitHub Dark",
		theme: Theme{
			Background: "#0d1117", SurfaceAlt: "#21262d", Border: "#30363d",
			Text: "#c9d1d9", TextMuted: "#8b949e",
			Critical: "#f85149", High: "#f0883e", Medium: "#d29922", Low: "#3fb950",
			Accent: "#58a6ff", Success: "#3fb950",
		},
	},
	{
		id: ThemeAyuDark, label: "Ayu Dark",
		theme: Theme{
			Background: "#0a0e14", SurfaceAlt: "#151a21", Border: "#242936",
			Text: "#bfbdb6", TextMuted: "#626a73",
			Critical: "#f07178", High: "#ffad66", Medium: "#ffd580", Low: "#bae67f",
			Accent: "#59c2ff", Success: "#bae67f",
		},
	},
	{
		id: ThemeNightOwl, label: "Night Owl",
		theme: Theme{
			Background: "#011627", SurfaceAlt: "#1d3b53", Border: "#234d70",
			Text: "#d6deeb", TextMuted: "#637777",
			Critical: "#ef5350", High: "#f78c6c", Medium: "#ffeb95", Low: "#c3e88d",
			Accent: "#82aaff", Success: "#c3e88d",
		},
	},
}

// ThemeIDs returns the ordered list of selectable theme identifiers.
func ThemeIDs() []string {
	ids := make([]string, len(themeRegistry))
	for i, entry := range themeRegistry {
		ids[i] = entry.id
	}
	return ids
}

// ThemeLabel returns the human-readable name for a theme ID.
func ThemeLabel(id string) string {
	for _, entry := range themeRegistry {
		if entry.id == id {
			return entry.label
		}
	}
	return id
}

// LookupTheme returns the palette for id, falling back to the default theme.
func LookupTheme(id string) Theme {
	for _, entry := range themeRegistry {
		if entry.id == id {
			return entry.theme
		}
	}
	return themeRegistry[0].theme
}

// DefaultTheme returns the built-in default palette.
func DefaultTheme() Theme { return themeRegistry[0].theme }

// NormalizeThemeID returns id when known, otherwise ThemeDefault.
func NormalizeThemeID(id string) string {
	for _, entry := range themeRegistry {
		if entry.id == id {
			return id
		}
	}
	return ThemeDefault
}

// themeIndex returns the selection index for id.
func themeIndex(id string) int {
	normalized := NormalizeThemeID(id)
	for i, themeID := range ThemeIDs() {
		if themeID == normalized {
			return i
		}
	}
	return 0
}
