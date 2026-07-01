package tui

import (
	"time"

	"charm.land/bubbles/v2/table"
	tea "charm.land/bubbletea/v2"
)

func (m model) updateMain(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	keyStr := msg.String()

	if m.confirmReset && keyStr != "R" {
		m.confirmReset = false
	}

	switch keyStr {
	case "q":
		if m.mode == paneDetail {
			m.mode = paneList
			m.updateDetailViewport()
			return m, nil
		}
		return m, tea.Quit
	case "?":
		m.modal = modalHelp
		return m, nil
	case "tab":
		if m.inlineDetail() {
			if m.mode == paneDetail {
				m.mode = paneList
			} else {
				m.mode = paneDetail
				m.updateDetailViewport()
			}
		}
		return m, nil
	case "/":
		m.modal = modalFilter
		m.searchBox.SetValue(m.filter.query)
		m.searchBox.Focus()
		return m, nil
	case "f":
		if len(m.selectedSet) > 0 {
			return m.runBatchFix()
		}
		return m.runFix()
	case "1":
		m.filter.severity = "critical"
		m.rebuildTable()
		return m, nil
	case "2":
		m.filter.severity = "high"
		m.rebuildTable()
		return m, nil
	case "3":
		m.filter.severity = "medium"
		m.rebuildTable()
		return m, nil
	case "4":
		m.filter.severity = "low"
		m.rebuildTable()
		return m, nil
	case "0":
		m.filter.severity = "all"
		m.rebuildTable()
		return m, nil
	case "s":
		m.cycleSourceFilter()
		m.rebuildTable()
		return m, nil
	case "r":
		m.cycleRemediationFilter()
		m.rebuildTable()
		return m, nil
	case "o":
		m.cycleSortOrder()
		m.rebuildTable()
		return m, nil
	case "O":
		if m.filter.sortDir == "asc" {
			m.filter.sortDir = "desc"
		} else {
			m.filter.sortDir = "asc"
		}
		m.rebuildTable()
		m.toast = "Sort: " + m.filter.sortBy + " (" + m.filter.sortDir + ")"
		m.toastUntil = time.Now().Add(3 * time.Second)
		return m, nil
	case "ctrl+a":
		visible := m.visibleFindings()
		selectableCount := 0
		allSelectableSelected := true
		for _, f := range visible {
			if !isBatchFixableFinding(f) {
				continue
			}
			selectableCount++
			if !m.selectedSet[f.ID] {
				allSelectableSelected = false
			}
		}
		if selectableCount > 0 && len(m.selectedSet) == selectableCount && allSelectableSelected {
			m.selectedSet = make(map[string]bool)
		} else {
			m.selectedSet = make(map[string]bool)
			for _, f := range visible {
				if !isBatchFixableFinding(f) {
					continue
				}
				m.selectedSet[f.ID] = true
			}
		}
		m.rebuildTable()
		return m, nil
	case "v":
		m.cycleServiceFilter()
		m.rebuildTable()
		return m, nil
	case "R":
		if m.confirmReset {
			m.filter.query = ""
			m.filter.severity = "all"
			m.filter.source = "all"
			m.filter.remediation = "all"
			m.filter.service = "all"
			m.rebuildTable()
			m.toast = "Filters cleared"
			m.toastUntil = time.Now().Add(3 * time.Second)
			m.confirmReset = false
		} else {
			m.confirmReset = true
			m.toast = "Press R again to confirm reset"
			m.toastUntil = time.Now().Add(5 * time.Second)
		}
		return m, nil
	case "ctrl+r":
		m.live.Recalculate()
		m.snap = m.live.Snapshot()
		m.snapOK = true
		m.toast = "Score recalculated"
		m.toastUntil = time.Now().Add(5 * time.Second)
		return m, nil
	case "ctrl+s":
		m = m.startRescan()
		return m, tickCmd()
	case "e":
		m.exportIdx = 0
		m.modal = modalExport
		return m, nil
	}

	if m.mode == paneDetail {
		switch keyStr {
		case "esc", "h", "left":
			m.mode = paneList
			m.updateDetailViewport()
			return m, nil
		case "g":
			m.viewport.GotoTop()
			return m, nil
		case "G":
			m.viewport.GotoBottom()
			return m, nil
		}
		var cmd tea.Cmd
		m.viewport, cmd = m.viewport.Update(msg)
		return m, cmd
	}

	switch keyStr {
	case " ", "space":
		m.toggleSelection()
		cursor := m.table.Cursor()
		m.rebuildTable()
		m.table.SetCursor(cursor)
		return m, nil
	case "g":
		m.table.SetCursor(0)
		m.updateDetailViewport()
		return m, nil
	case "G":
		visible := m.visibleFindings()
		if len(visible) > 0 {
			m.table.SetCursor(len(visible) - 1)
			m.updateDetailViewport()
		}
		return m, nil
	case "enter", "l", "right":
		visible := m.visibleFindings()
		cursor := m.table.Cursor()
		if cursor >= 0 && cursor < len(visible) {
			m.mode = paneDetail
			m.updateDetailViewport()
		}
		return m, nil
	}

	var cmd tea.Cmd
	m.table, cmd = m.table.Update(msg)
	if m.inlineDetail() {
		m.updateDetailViewport()
	}
	return m, cmd
}

func (m model) updateModal(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch m.modal {
	case modalHelp:
		switch msg.String() {
		case "q", "esc", "?", "enter":
			m.modal = modalNone
		}
	case modalFilter:
		switch msg.String() {
		case "esc":
			m.modal = modalNone
			m.searchBox.Blur()
			return m, nil
		case "enter":
			m.filter.query = m.searchBox.Value()
			m.modal = modalNone
			m.searchBox.Blur()
			m.rebuildTable()
			return m, nil
		}
		var cmd tea.Cmd
		m.searchBox, cmd = m.searchBox.Update(msg)
		return m, cmd
	case modalDryRun:
		switch msg.String() {
		case "up", "k":
			if m.dryRunApplyIdx > 0 {
				m.dryRunApplyIdx--
			}
		case "down", "j":
			if m.dryRunApplyIdx < len(m.dryRunActions)-1 {
				m.dryRunApplyIdx++
			}
		case "enter", "l":
			m.fixActionIdx = m.dryRunApplyIdx
			if m.fixTarget != nil && m.fixActionIdx < len(m.fixTarget.Actions) {
				if m.fixTarget.Actions[m.fixActionIdx].Warning != "" {
					m.modal = modalFixConfirm
				} else {
					m.modal = modalNone
					m.toast = "Applying fix..."
					m.toastUntil = time.Now().Add(5 * time.Second)
					m2, cmd := m.applyFix()
					return m2, cmd
				}
			}
		case "q", "esc":
			m.fixTarget = nil
			m.dryRunActions = nil
			m.modal = modalNone
		}
	case modalFixConfirm:
		switch msg.String() {
		case "y", "Y":
			m.modal = modalNone
			m.dryRunActions = nil
			m2, cmd := m.applyFix()
			return m2, cmd
		case "n", "N", "q", "esc":
			m.fixTarget = nil
			m.dryRunActions = nil
			m.modal = modalNone
		}
	case modalFixResult:
		m.fixTarget = nil
		m.dryRunActions = nil
		m.modal = modalNone
	case modalFixProgress:
		return m, nil
	case modalExport:
		switch msg.String() {
		case "up", "k":
			if m.exportIdx > 0 {
				m.exportIdx--
			}
		case "down", "j":
			if m.exportIdx < len(exportFormats)-1 {
				m.exportIdx++
			}
		case "enter", "l":
			m.modal = modalNone
			m.exportReport()
		case "q", "esc":
			m.modal = modalNone
		}
	}
	return m, nil
}

// Table column definitions for different layouts.
var tableColumnsFull = []table.Column{
	{Title: " ", Width: 3},
	{Title: "Severity", Width: 8},
	{Title: "Source", Width: 8},
	{Title: "ID", Width: 14},
	{Title: "Finding", Width: 40},
	{Title: "Fix", Width: 11},
}
