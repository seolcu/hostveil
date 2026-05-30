package tui

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

func DefaultTheme() Theme { return webTheme }

var webTheme = Theme{
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
}
