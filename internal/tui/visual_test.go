package tui

import (
	"strings"
	"testing"

	"charm.land/lipgloss/v2"
	"github.com/seolcu/hostveil/internal/domain"
)

func TestStyledTableSeverity_ColorsActiveAndFixedFindings(t *testing.T) {
	t.Parallel()
	theme := DefaultTheme()

	active := styledTableSeverity(theme, domain.Finding{
		Severity: domain.SeverityCritical,
	})
	if !strings.Contains(active, "CRITICAL") {
		t.Fatalf("active severity should render label, got %q", active)
	}
	if lipgloss.Width(active) == 0 {
		t.Fatal("active severity should include styling")
	}

	fixed := styledTableSeverity(theme, domain.Finding{
		Severity: domain.SeverityHigh,
		Fixed:    true,
	})
	if !strings.Contains(fixed, "✓") {
		t.Fatalf("fixed severity should render checkmark, got %q", fixed)
	}
}

func TestStyledTableTitle_StrikesThroughFixedFindings(t *testing.T) {
	t.Parallel()
	theme := DefaultTheme()

	active := styledTableTitle(theme, domain.Finding{Title: "Open finding"}, 40)
	if active != "Open finding" {
		t.Fatalf("active title should render plainly, got %q", active)
	}

	fixed := styledTableTitle(theme, domain.Finding{Title: "Resolved finding", Fixed: true}, 40)
	if fixed == active || !strings.Contains(fixed, ";9m") {
		t.Fatalf("fixed title should be struck through, got %q", fixed)
	}
}

func TestRenderSelectableItem_HighlightsSelection(t *testing.T) {
	t.Parallel()
	theme := DefaultTheme()

	unselected := renderSelectableItem(theme, "JSON (full data)", false)
	if !strings.Contains(unselected, "JSON (full data)") || !strings.HasPrefix(unselected, "  ") {
		t.Fatalf("unselected item should be indented with label, got %q", unselected)
	}

	selected := renderSelectableItem(theme, "CSV (spreadsheet)", true)
	if !strings.Contains(selected, "CSV (spreadsheet)") || !strings.HasPrefix(selected, "> ") {
		t.Fatalf("selected item should use cursor prefix, got %q", selected)
	}
}

func TestRenderFixResultModal_ColorsSuccessAndFailure(t *testing.T) {
	t.Parallel()
	m := readyModelForRenderRegression(t, nil, 120, 32)

	m.fixResult = "✓ Hardened SSH"
	success := m.renderFixResultModal()
	if !strings.Contains(success, "✓ Hardened SSH") {
		t.Fatalf("success modal should include result text:\n%s", success)
	}

	m.fixResult = "✗ permission denied"
	failure := m.renderFixResultModal()
	if !strings.Contains(failure, "permission denied") {
		t.Fatalf("failure modal should include error text:\n%s", failure)
	}
}

func TestView_ModalOverlayDimsUnderlyingContent(t *testing.T) {
	t.Parallel()
	m := readyModelForRenderRegression(t, makeTestFindings(1), 120, 32)
	m.modal = modalHelp

	base := m.renderMain()
	overlay := m.renderWithModal(base)
	if overlay == base {
		t.Fatal("modal overlay should change rendered output")
	}
	if !strings.Contains(overlay, "Help") {
		t.Fatalf("overlay should still include modal content:\n%s", overlay)
	}
}

func TestPaintPanelBlock_FillsFullLineWidth(t *testing.T) {
	t.Parallel()
	theme := DefaultTheme()
	const width = 40
	block := paintPanelBlock(theme, width, "short")
	for i, line := range strings.Split(block, "\n") {
		if lipgloss.Width(line) != width {
			t.Fatalf("line %d width = %d, want %d: %q", i+1, lipgloss.Width(line), width, line)
		}
	}
}

func TestPaintPanelLineBG_PreservesSelectionWidth(t *testing.T) {
	t.Parallel()
	theme := DefaultTheme()
	const width = 30
	highlight := lipgloss.NewStyle().Foreground(lipgloss.Color(theme.Text)).Bold(true).Render("selected")
	line := paintPanelLineBG(theme, width, highlight, theme.Border)
	if !strings.Contains(line, "selected") {
		t.Fatalf("paint should preserve row content:\n%s", line)
	}
	if lipgloss.Width(line) != width {
		t.Fatalf("painted line width = %d, want %d", lipgloss.Width(line), width)
	}
}

func TestReanchorPanelBG_KeepsBackgroundAfterStyleReset(t *testing.T) {
	t.Parallel()
	theme := DefaultTheme()
	styled := lipgloss.NewStyle().Foreground(lipgloss.Color(theme.Critical)).Bold(true).Render("CRITICAL")
	line := paintPanelLineBG(theme, 24, " "+styled+"  tail", theme.SurfaceAlt)
	if strings.Contains(line, "CRITICAL\x1b[m") {
		t.Fatalf("bare reset after styled text leaves background gaps:\n%s", line)
	}
	if !strings.Contains(line, "48;") {
		t.Fatalf("expected background SGR codes in output:\n%s", line)
	}
}

func TestPaintTableView_HighlightsCursorRow(t *testing.T) {
	t.Parallel()
	m := readyModelForRenderRegression(t, makeTestFindings(3), 120, 32)
	m.table.SetCursor(1)
	raw := m.table.View()
	painted := m.paintTableView(m.theme(), raw, 60)
	lines := strings.Split(painted, "\n")
	if len(lines) < 3 {
		t.Fatalf("expected header plus data rows, got %d lines", len(lines))
	}
	if lipgloss.Width(lines[2]) != 60 {
		t.Fatalf("row width = %d, want 60", lipgloss.Width(lines[2]))
	}
}

func TestJoinPanelSections_GapLinesMatchPanelFill(t *testing.T) {
	t.Parallel()
	theme := DefaultTheme()
	const width = 30
	block := joinPanelSections(theme, width, "top", "bottom", 2)
	lines := strings.Split(block, "\n")
	if len(lines) != 4 {
		t.Fatalf("expected top + 2 gaps + bottom, got %d lines", len(lines))
	}
	for i, line := range lines[1:3] {
		if lipgloss.Width(line) != width {
			t.Fatalf("gap line %d width = %d, want %d", i, lipgloss.Width(line), width)
		}
	}
}
