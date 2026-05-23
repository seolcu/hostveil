package tui

type Theme struct {
	Background string
	Surface    string
	Card       string
	Border     string
	Text       string
	TextMuted  string
	TextBright string
	Accent     string
	Critical   string
	High       string
	Medium     string
	Low        string
	Success    string
}

func DefaultTheme() Theme {
	return TokyoNightTheme()
}

func TokyoNightTheme() Theme {
	return Theme{
		Background: "#0f0f14",
		Surface:    "#16161e",
		Card:       "#1a1b26",
		Border:     "#2f3348",
		Text:       "#a9b1d6",
		TextMuted:  "#565f89",
		TextBright: "#c0caf5",
		Accent:     "#7aa2f7",
		Critical:   "#f7768e",
		High:       "#ff9e64",
		Medium:     "#e0af68",
		Low:        "#9ece6a",
		Success:    "#73daca",
	}
}

func DraculaTheme() Theme {
	return Theme{
		Background: "#1a1b2e",
		Surface:    "#21222c",
		Card:       "#282a36",
		Border:     "#44475a",
		Text:       "#f8f8f2",
		TextMuted:  "#6272a4",
		TextBright: "#f1fa8c",
		Accent:     "#bd93f9",
		Critical:   "#ff5555",
		High:       "#ffb86c",
		Medium:     "#f1fa8c",
		Low:        "#50fa7b",
		Success:    "#8be9fd",
	}
}

func NordTheme() Theme {
	return Theme{
		Background: "#2e3440",
		Surface:    "#3b4252",
		Card:       "#434c5e",
		Border:     "#4c566a",
		Text:       "#e5e9f0",
		TextMuted:  "#81a1c1",
		TextBright: "#8fbcbb",
		Accent:     "#88c0d0",
		Critical:   "#bf616a",
		High:       "#d08770",
		Medium:     "#ebcb8b",
		Low:        "#a3be8c",
		Success:    "#8fbcbb",
	}
}

func CatppuccinTheme() Theme {
	return Theme{
		Background: "#1e1e2e",
		Surface:    "#181825",
		Card:       "#242436",
		Border:     "#45475a",
		Text:       "#cdd6f4",
		TextMuted:  "#a6adc8",
		TextBright: "#b4befe",
		Accent:     "#89b4fa",
		Critical:   "#f38ba8",
		High:       "#fab387",
		Medium:     "#f9e2af",
		Low:        "#a6e3a1",
		Success:    "#94e2d5",
	}
}

func GruvboxTheme() Theme {
	return Theme{
		Background: "#282828",
		Surface:    "#1d2021",
		Card:       "#32302f",
		Border:     "#504945",
		Text:       "#ebdbb2",
		TextMuted:  "#a89984",
		TextBright: "#fbf1c7",
		Accent:     "#83a598",
		Critical:   "#fb4934",
		High:       "#fe8019",
		Medium:     "#fabd2f",
		Low:        "#b8bb26",
		Success:    "#8ec07c",
	}
}

var themes = map[string]func() Theme{
	"tokyo-night": TokyoNightTheme,
	"dracula":     DraculaTheme,
	"nord":        NordTheme,
	"catppuccin":  CatppuccinTheme,
	"gruvbox":     GruvboxTheme,
}

// themeOrder defines the display order for themes
var themeOrder = []string{"tokyo-night", "dracula", "nord", "catppuccin", "gruvbox"}

// GradeColor returns the appropriate theme color for a score (0-100).
func (t Theme) GradeColor(score uint8) string {
	switch {
	case score >= 80:
		return t.Success
	case score >= 50:
		return t.Medium
	default:
		return t.Critical
	}
}

func ThemeNames() []string {
	// Return a copy to prevent modification
	names := make([]string, len(themeOrder))
	copy(names, themeOrder)
	return names
}

func GetTheme(name string) Theme {
	if fn, ok := themes[name]; ok {
		return fn()
	}
	return DefaultTheme()
}
