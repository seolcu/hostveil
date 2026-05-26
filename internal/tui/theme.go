package tui

type Theme struct {
	Name       string
	Background string
	Surface    string
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

func DefaultTheme() Theme { return allThemes[0] }
func AllThemes() []Theme  { return allThemes }

var allThemes = []Theme{
	{
		Name: "Tokyo Night", Background: "#1a1b26", Surface: "#24283b",
		Border: "#565f89", Text: "#a9b1d6", TextMuted: "#565f89",
		Critical: "#f7768e", High: "#ff9e64", Medium: "#e0af68",
		Low: "#9ece6a", Accent: "#7aa2f7", Success: "#9ece6a",
	},
	{
		Name: "Catppuccin Mocha", Background: "#1e1e2e", Surface: "#313244",
		Border: "#585b70", Text: "#cdd6f4", TextMuted: "#585b70",
		Critical: "#f38ba8", High: "#fab387", Medium: "#f9e2af",
		Low: "#a6e3a1", Accent: "#89b4fa", Success: "#a6e3a1",
	},
	{
		Name: "Catppuccin Macchiato", Background: "#24273a", Surface: "#363a4f",
		Border: "#5b6078", Text: "#cad3f5", TextMuted: "#5b6078",
		Critical: "#f38ba8", High: "#fab387", Medium: "#f9e2af",
		Low: "#a6e3a1", Accent: "#89b4fa", Success: "#a6e3a1",
	},
	{
		Name: "Catppuccin Frappe", Background: "#303446", Surface: "#414559",
		Border: "#626880", Text: "#c6d0f5", TextMuted: "#626880",
		Critical: "#f38ba8", High: "#fab387", Medium: "#f9e2af",
		Low: "#a6e3a1", Accent: "#89b4fa", Success: "#a6e3a1",
	},
	{
		Name: "Catppuccin Latte", Background: "#eff1f5", Surface: "#e6e9ef",
		Border: "#9ca0b0", Text: "#4c4f69", TextMuted: "#9ca0b0",
		Critical: "#d20f39", High: "#fe640b", Medium: "#df8e1d",
		Low: "#40a02b", Accent: "#1e66f5", Success: "#40a02b",
	},
	{
		Name: "Gruvbox Dark Hard", Background: "#1d2021", Surface: "#3c3836",
		Border: "#504945", Text: "#ebdbb2", TextMuted: "#928374",
		Critical: "#fb4934", High: "#fe8019", Medium: "#fabd2f",
		Low: "#b8bb26", Accent: "#83a598", Success: "#b8bb26",
	},
	{
		Name: "Gruvbox Dark Medium", Background: "#282828", Surface: "#3c3836",
		Border: "#504945", Text: "#ebdbb2", TextMuted: "#928374",
		Critical: "#fb4934", High: "#fe8019", Medium: "#fabd2f",
		Low: "#b8bb26", Accent: "#83a598", Success: "#b8bb26",
	},
	{
		Name: "Gruvbox Dark Soft", Background: "#32302f", Surface: "#3c3836",
		Border: "#504945", Text: "#ebdbb2", TextMuted: "#928374",
		Critical: "#fb4934", High: "#fe8019", Medium: "#fabd2f",
		Low: "#b8bb26", Accent: "#83a598", Success: "#b8bb26",
	},
	{
		Name: "Gruvbox Light Hard", Background: "#f9f5d7", Surface: "#ebdbb2",
		Border: "#d5c4a1", Text: "#3c3836", TextMuted: "#928374",
		Critical: "#cc241d", High: "#d65d0e", Medium: "#d79921",
		Low: "#98971a", Accent: "#458588", Success: "#98971a",
	},
	{
		Name: "Gruvbox Light Medium", Background: "#fbf1c7", Surface: "#ebdbb2",
		Border: "#d5c4a1", Text: "#3c3836", TextMuted: "#928374",
		Critical: "#cc241d", High: "#d65d0e", Medium: "#d79921",
		Low: "#98971a", Accent: "#458588", Success: "#98971a",
	},
	{
		Name: "Gruvbox Light Soft", Background: "#f2e5bc", Surface: "#ebdbb2",
		Border: "#d5c4a1", Text: "#3c3836", TextMuted: "#928374",
		Critical: "#cc241d", High: "#d65d0e", Medium: "#d79921",
		Low: "#98971a", Accent: "#458588", Success: "#98971a",
	},
	{
		Name: "Nord", Background: "#2e3440", Surface: "#3b4252",
		Border: "#4c566a", Text: "#eceff4", TextMuted: "#4c566a",
		Critical: "#bf616a", High: "#d08770", Medium: "#ebcb8b",
		Low: "#a3be8c", Accent: "#81a1c1", Success: "#a3be8c",
	},
	{
		Name: "Dracula", Background: "#282a36", Surface: "#44475a",
		Border: "#6272a4", Text: "#f8f8f2", TextMuted: "#6272a4",
		Critical: "#ff5555", High: "#ffb86c", Medium: "#f1fa8c",
		Low: "#50fa7b", Accent: "#bd93f9", Success: "#50fa7b",
	},
}
