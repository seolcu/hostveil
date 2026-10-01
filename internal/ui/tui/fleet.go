package tui

import (
	"context"
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/seolcu/hostveil/internal/core"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/textwidth"
	"github.com/seolcu/hostveil/internal/ui/theme"
)

// FleetOpts configures the fleet screen.
type FleetOpts struct {
	Theme theme.Theme
	Fleet core.FleetOptions
}

// RunFleet scans the hosts and shows them side by side: one row per host,
// worst first, and the selected host's standing findings beside it.
//
// The screen is read-only on purpose. A fix is applied on the host it fixes,
// with that host's preview, backup and rollback; doing it from here would
// mean a second apply path over SSH, which is the thing "one engine, three
// thin UIs" exists to rule out. The screen says where to go instead.
func RunFleet(ctx context.Context, engine *core.Engine, hosts []string, opts FleetOpts) error {
	_, err := tea.NewProgram(newFleetModel(ctx, engine, hosts, opts)).Run()
	return err
}

type fleetDoneMsg model.Fleet

type fleetModel struct {
	ctx     context.Context
	engine  *core.Engine
	hosts   []string
	opts    core.FleetOptions
	st      *styles
	entries []model.FleetEntry
	loading bool
	cursor  int
	width   int
	height  int
}

func newFleetModel(ctx context.Context, engine *core.Engine, hosts []string, opts FleetOpts) *fleetModel {
	return &fleetModel{ctx: ctx, engine: engine, hosts: hosts, opts: opts.Fleet, st: newStyles(opts.Theme), loading: true}
}

func (m *fleetModel) scan() tea.Cmd {
	ctx, e, hosts, opts := m.ctx, m.engine, m.hosts, m.opts
	if ctx == nil {
		ctx = context.Background()
	}
	return func() tea.Msg { return fleetDoneMsg(e.Fleet(ctx, hosts, opts)) }
}

func (m *fleetModel) Init() tea.Cmd { return m.scan() }

func (m *fleetModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case fleetDoneMsg:
		m.entries = model.Fleet(msg).WorstFirst()
		m.loading = false
		if m.cursor >= len(m.entries) {
			m.cursor = 0
		}
	case tea.KeyPressMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			return m, tea.Quit
		case "j", "down":
			if m.cursor < len(m.entries)-1 {
				m.cursor++
			}
		case "k", "up":
			if m.cursor > 0 {
				m.cursor--
			}
		case "r":
			if !m.loading {
				m.loading = true
				return m, m.scan()
			}
		}
	}
	return m, nil
}

func (m *fleetModel) View() tea.View {
	return tea.View{Content: m.render(), AltScreen: true, BackgroundColor: m.st.cInk}
}

// render draws the screen as plain lines, so a test can read it without a
// terminal.
func (m *fleetModel) render() string {
	s := m.st
	width := m.width
	if width <= 0 {
		width = 100
	}
	var b strings.Builder
	title := s.brand.Render("hostveil fleet") + s.dim.Render(fmt.Sprintf("  ·  %d host(s) over SSH", len(m.hosts)))
	b.WriteString(title + "\n\n")

	if m.loading {
		b.WriteString(s.dim.Render("Scanning… each host runs `hostveil scan --json` over SSH. This can take minutes on a host with many images.") + "\n")
		b.WriteString("\n" + s.dim.Render("q quit") + "\n")
		return b.String()
	}

	hostW := len("HOST")
	for _, e := range m.entries {
		hostW = max(hostW, textwidth.Of(e.Host))
	}
	hostW = min(hostW, 32)
	b.WriteString(s.dim.Render(fmt.Sprintf("  %-*s  %5s  %4s %4s %4s", hostW, "HOST", "SCORE", "HIGH", "MED", "LOW")) + "\n")
	for i, e := range m.entries {
		host := textwidth.Truncate(e.Host, hostW)
		host += strings.Repeat(" ", hostW-textwidth.Of(host))
		var row string
		if e.Report == nil {
			row = fmt.Sprintf("%s  %s", host, lipgloss.NewStyle().Foreground(s.cCrit).Render("  —   could not scan"))
		} else {
			high, med, low := countStanding(e.Report.Findings)
			score := s.dim.Render("  N/A")
			if e.Report.Score.Applicable {
				score = lipgloss.NewStyle().Foreground(s.band(e.Report.Score.Overall)).Render(fmt.Sprintf("%5d", e.Report.Score.Overall))
			}
			row = fmt.Sprintf("%s  %s  %4d %4d %4d", host, score, high, med, low)
		}
		marker := "  "
		if i == m.cursor {
			marker = s.accent.Render("▸ ")
		}
		b.WriteString(marker + row + "\n")
	}

	b.WriteString("\n" + strings.Repeat("─", min(width, 100)) + "\n")
	if len(m.entries) > 0 {
		b.WriteString(m.detail(m.entries[m.cursor], width))
	}
	b.WriteString("\n" + s.dim.Render("j/k move   r rescan   q quit") + "\n")
	return b.String()
}

// detail is the selected host: why it could not be scanned, or what is
// standing on it, most severe first.
func (m *fleetModel) detail(e model.FleetEntry, width int) string {
	s := m.st
	var b strings.Builder
	b.WriteString(s.bone.Bold(true).Render(e.Host) + "\n")
	if e.Report == nil {
		b.WriteString(lipgloss.NewStyle().Foreground(s.cCrit).Render(e.Error) + "\n")
		return b.String()
	}
	if n := e.Report.IncompleteDomains(); n > 0 {
		b.WriteString(s.dim.Render(fmt.Sprintf("%d domain(s) did not fully run there — `ssh %s hostveil scan` says which.", n, e.Host)) + "\n")
	}
	shown := 0
	for _, sev := range []model.Severity{model.SeverityHigh, model.SeverityMedium, model.SeverityLow} {
		for _, f := range e.Report.Findings {
			if !f.Active() || f.Severity != sev || shown >= 10 {
				continue
			}
			label := lipgloss.NewStyle().Foreground(s.severityColor(sev)).Render(fmt.Sprintf("%-4s", sev.Abbr()))
			// Truncate the plain text only; cutting through the label's
			// escape sequence would leave the colour on for the next line.
			rest := textwidth.Truncate(fmt.Sprintf("%-28s %s", f.ID, f.Title), max(width-5, 10))
			b.WriteString(label + " " + rest + "\n")
			shown++
		}
	}
	if shown == 0 {
		b.WriteString(s.safe.Render("Nothing standing.") + "\n")
	}
	b.WriteString("\n" + s.dim.Render("Fixes are applied on the host itself, with its own preview and rollback: ssh "+e.Host+" hostveil") + "\n")
	return b.String()
}

func countStanding(fs []model.Finding) (high, med, low int) {
	for _, f := range fs {
		if !f.Active() {
			continue
		}
		switch f.Severity {
		case model.SeverityHigh:
			high++
		case model.SeverityMedium:
			med++
		case model.SeverityLow:
			low++
		}
	}
	return high, med, low
}
