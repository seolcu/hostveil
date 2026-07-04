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
)

var themeCatalog = map[string]Theme{
	ThemeDefault: {
		Background: "#090b12",
		SurfaceAlt: "#171c2b",
		Border:     "#2f3a52",
		Text:       "#e7ecf8",
		TextMuted:  "#8390ad",
		Critical:   "#ff5573",
		High:       "#ff9868",
		Medium:     "#f7c66b",
		Low:        "#87d978",
		Accent:     "#64c8ff",
		Success:    "#87d978",
	},
	ThemeTokyoNight: {
		Background: "#1a1b26",
		SurfaceAlt: "#24283b",
		Border:     "#292e42",
		Text:       "#c0caf5",
		TextMuted:  "#565f89",
		Critical:   "#f7768e",
		High:       "#ff9e64",
		Medium:     "#e0af68",
		Low:        "#9ece6a",
		Accent:     "#7aa2f7",
		Success:    "#9ece6a",
	},
	ThemeCatppuccin: {
		Background: "#1e1e2e",
		SurfaceAlt: "#313244",
		Border:     "#45475a",
		Text:       "#cdd6f4",
		TextMuted:  "#6c7086",
		Critical:   "#f38ba8",
		High:       "#fab387",
		Medium:     "#f9e2af",
		Low:        "#a6e3a1",
		Accent:     "#89b4fa",
		Success:    "#a6e3a1",
	},
	ThemeNord: {
		Background: "#2e3440",
		SurfaceAlt: "#434c5e",
		Border:     "#4c566a",
		Text:       "#eceff4",
		TextMuted:  "#616e88",
		Critical:   "#bf616a",
		High:       "#d08770",
		Medium:     "#ebcb8b",
		Low:        "#a3be8c",
		Accent:     "#88c0d0",
		Success:    "#a3be8c",
	},
}

var themeLabels = map[string]string{
	ThemeDefault:    "Default",
	ThemeTokyoNight: "Tokyo Night",
	ThemeCatppuccin: "Catppuccin",
	ThemeNord:       "Nord",
}

// ThemeIDs returns the ordered list of selectable theme identifiers.
func ThemeIDs() []string {
	return []string{ThemeDefault, ThemeTokyoNight, ThemeCatppuccin, ThemeNord}
}

// ThemeLabel returns the human-readable name for a theme ID.
func ThemeLabel(id string) string {
	if label, ok := themeLabels[id]; ok {
		return label
	}
	return id
}

// LookupTheme returns the palette for id, falling back to the default theme.
func LookupTheme(id string) Theme {
	if t, ok := themeCatalog[id]; ok {
		return t
	}
	return themeCatalog[ThemeDefault]
}

// DefaultTheme returns the built-in default palette.
func DefaultTheme() Theme { return themeCatalog[ThemeDefault] }

// NormalizeThemeID returns id when known, otherwise ThemeDefault.
func NormalizeThemeID(id string) string {
	if _, ok := themeCatalog[id]; ok {
		return id
	}
	return ThemeDefault
}

// themeIndex returns the selection index for id.
func themeIndex(id string) int {
	for i, themeID := range ThemeIDs() {
		if themeID == NormalizeThemeID(id) {
			return i
		}
	}
	return 0
}
