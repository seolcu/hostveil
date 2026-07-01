package tui

import (
	"strings"

	"charm.land/bubbles/v2/table"
	"github.com/seolcu/hostveil/internal/domain"
)

func (m *model) rebuildTable() {
	m.live.Recalculate()
	m.snap = m.live.Snapshot()
	m.snapOK = true
	m.invalidateVisibleCache()
	visible := m.visibleFindings()
	rows := make([]table.Row, len(visible))
	layout := m.tableLayout()
	cursor := m.table.Cursor()
	for i, f := range visible {
		checkbox := "◇"
		if f.Remediation == domain.RemediationUnavailable {
			checkbox = "─"
		} else if m.selectedSet[f.ID] {
			checkbox = "◆"
		}
		sevText := strings.ToUpper(f.Severity.String())
		src := f.Source.String()
		id := shortID(f.ID)
		title := findingTitle(f)
		fixLabel := remediationShortLabel(f.Remediation)
		if f.Fixed {
			sevText = "✓"
			src = ""
			title = "✓ " + title
			fixLabel = "Fixed"
		}
		switch layout {
		case "compact":
			rows[i] = table.Row{checkbox, sevText, fit(title, m.findingColumnWidth(layout))}
		case "medium":
			rows[i] = table.Row{checkbox, sevText, id, fit(title, m.findingColumnWidth(layout)), fixLabel}
		default:
			rows[i] = table.Row{checkbox, sevText, src, id, fit(title, m.findingColumnWidth(layout)), fixLabel}
		}
	}
	m.table.SetRows(nil)
	m.updateTableColumns()
	m.table.SetRows(rows)
	m.table.SetCursor(cursor)
	m.table.SetWidth(m.listTableWidth())
	// Cap table height to the data so we don't render empty rows in the
	// table body; the leftover space lives below the table inside the panel.
	tableH := m.listHeight()
	if rows := len(visible); rows+1 < tableH {
		tableH = rows + 1
	}
	m.table.SetHeight(tableH)
	if m.width > 0 && m.height > 0 {
		m.updateDetailViewport()
	}
}

func (m *model) updateDetailViewport() {
	contentWidth := m.detailContentWidth()
	if m.phase == "loading" {
		m.viewport.SetContent("Scanning in progress...\n\nResults will appear when scans complete.")
		m.viewport.SetWidth(contentWidth)
		m.viewport.SetHeight(m.detailHeight())
		m.viewport.GotoTop()
		return
	}
	visible := m.visibleFindings()
	idx := m.table.Cursor()
	if idx < 0 || idx >= len(visible) {
		m.viewport.SetContent("")
		return
	}
	t := m.theme()
	content := renderDetailContent(t, &visible[idx], contentWidth)
	m.viewport.SetContent(content)
	m.viewport.SetWidth(contentWidth)
	m.viewport.SetHeight(m.detailHeight())
	m.viewport.GotoTop()
}

func (m model) tableLayout() string {
	w := m.listWidth()
	if w < 64 {
		return "compact"
	}
	if w < 88 {
		return "medium"
	}
	return "full"
}

func (m *model) updateTableColumns() {
	switch m.tableLayout() {
	case "compact":
		m.table.SetColumns([]table.Column{
			{Title: " ", Width: 3},
			{Title: "Severity", Width: 8},
			{Title: "Finding", Width: m.findingColumnWidth("compact")},
		})
	case "medium":
		m.table.SetColumns([]table.Column{
			{Title: " ", Width: 3},
			{Title: "Severity", Width: 8},
			{Title: "ID", Width: 14},
			{Title: "Finding", Width: m.findingColumnWidth("medium")},
			{Title: "Fix", Width: 11},
		})
	default:
		m.table.SetColumns([]table.Column{
			{Title: " ", Width: 3},
			{Title: "Severity", Width: 8},
			{Title: "Source", Width: 7},
			{Title: "ID", Width: 14},
			{Title: "Finding", Width: m.findingColumnWidth("full")},
			{Title: "Fix", Width: 11},
		})
	}
}

func (m model) findingColumnWidth(layout string) int {
	w := m.listTableWidth()
	switch layout {
	case "compact":
		return max(12, w-3-8-6)
	case "medium":
		return max(14, w-3-8-14-11-18)
	default:
		return max(16, w-3-8-7-14-11-24)
	}
}

func (m model) listWidth() int {
	fw := m.filterWidth()
	if fw > 0 {
		return max(52, m.width-fw-m.detailWidth()-4)
	}
	if m.splitDetail() {
		return max(52, m.width-m.detailWidth()-2)
	}
	return max(1, m.width-4)
}

func (m model) listTableWidth() int {
	return max(20, m.listWidth()-4)
}

func (m model) listHeight() int {
	h := m.bodyHeight() - 12
	if h < 4 {
		return 4
	}
	return h
}

func (m model) detailWidth() int {
	if m.filterWidth() > 0 {
		remaining := m.width - m.filterWidth() - 4
		d := remaining * 2 / 5
		if d < 44 {
			return 44
		}
		if d > 66 {
			return 66
		}
		return d
	}
	if m.splitDetail() {
		d := m.width * 2 / 5
		if d < 42 {
			return 42
		}
		if d > 58 {
			return 58
		}
		return d
	}
	return max(1, m.width-4)
}

func (m model) detailHeight() int {
	h := m.bodyHeight() - 6
	if h < 4 {
		return 4
	}
	return h
}

func (m model) bodyHeight() int {
	if m.height <= 0 || m.width <= 0 {
		return 10
	}
	h := m.height - m.headerH - m.metricsH
	if h < 4 {
		return 4
	}
	return h
}

func (m model) splitDetail() bool {
	return m.width >= 116
}

func (m model) inlineDetail() bool {
	return m.filterWidth() > 0 || m.splitDetail()
}

func (m model) detailContentWidth() int {
	return max(20, m.detailWidth()-8)
}

func (m model) panelAt(x int) paneMode {
	fw := m.filterWidth()
	if fw > 0 {
		listStart := fw + 2
		listEnd := listStart + m.listWidth() + 2
		if x >= listEnd {
			return paneDetail
		}
		return paneList
	}
	if m.splitDetail() {
		listEnd := m.listWidth() + 2
		if x >= listEnd {
			return paneDetail
		}
		return paneList
	}
	return m.mode
}
