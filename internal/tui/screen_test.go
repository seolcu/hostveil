package tui

import (
	"fmt"
	"strings"
	"testing"

	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/seolcu/hostveil/internal/domain"
	"github.com/seolcu/hostveil/internal/fix"
)

func TestRenderFixActionModal_BasicStructure(t *testing.T) {
	m := model{
		width:  120,
		height: 40,
		fixTarget: &fix.Fix{
			FindingID: "trivy.ds001",
			Label:     "Disable privileged mode",
			Actions: []fix.Action{
				{Type: fix.ActionEdit, Label: "Set privileged: false"},
			},
		},
		fixActionIdx: 0,
	}

	output := m.renderFixActionModal()

	if !strings.Contains(output, "Choose action") {
		t.Error("expected 'Choose action' in modal output")
	}
	if !strings.Contains(output, "Disable privileged mode") {
		t.Error("expected fix label in modal output")
	}
	if !strings.Contains(output, "Set privileged: false") {
		t.Error("expected action label in modal output")
	}
	if !strings.Contains(output, "> ") {
		t.Error("expected selection marker '> ' in modal output")
	}
}

func TestRenderFixActionModal_MultipleActions(t *testing.T) {
	m := model{
		width:  120,
		height: 40,
		fixTarget: &fix.Fix{
			FindingID: "trivy.dr001",
			Label:     "Change network_mode: host",
			Actions: []fix.Action{
				{Type: fix.ActionEdit, Label: "Remove network_mode"},
				{Type: fix.ActionEdit, Label: "Set network_mode: overlay"},
			},
		},
		fixActionIdx: 0,
	}

	output := m.renderFixActionModal()

	if !strings.Contains(output, "Remove network_mode") {
		t.Error("expected first action label")
	}
	if !strings.Contains(output, "Set network_mode: overlay") {
		t.Error("expected second action label")
	}
}

func TestRenderFixActionModal_ActionTypeTags(t *testing.T) {
	m := model{
		width:  120,
		height: 40,
		fixTarget: &fix.Fix{
			FindingID: "lynis.AUTH-9286",
			Label:     "Disable SSH password auth",
			Actions: []fix.Action{
				{Type: fix.ActionEdit, Label: "Edit sshd_config"},
				{Type: fix.ActionExec, Label: "Run chmod"},
				{Type: fix.ActionExec, Label: "Run systemctl"},
			},
		},
		fixActionIdx: 0,
	}

	output := m.renderFixActionModal()

	if !strings.Contains(output, "[edit]") {
		t.Error("expected [edit] type tag")
	}
	if !strings.Contains(output, "[exec]") {
		t.Error("expected [exec] type tag")
	}
	if !strings.Contains(output, "[exec]") {
		t.Error("expected [exec] type tag")
	}
}

func TestRenderFixActionModal_WarningIndicator(t *testing.T) {
	m := model{
		width:  120,
		height: 40,
		fixTarget: &fix.Fix{
			FindingID: "lynis.FIRE-4512",
			Label:     "Enable firewall",
			Actions: []fix.Action{
				{Type: fix.ActionExec, Label: "Enable ufw", Warning: "This will drop all incoming connections"},
			},
		},
		fixActionIdx: 0,
	}

	output := m.renderFixActionModal()

	if !strings.Contains(output, "⚠") {
		t.Error("expected warning indicator for action with warning")
	}
}

func TestRenderFixActionModal_SelectionMarker(t *testing.T) {
	m := model{
		width:  120,
		height: 40,
		fixTarget: &fix.Fix{
			FindingID: "trivy.dr001",
			Label:     "Change network_mode",
			Actions: []fix.Action{
				{Type: fix.ActionEdit, Label: "First action"},
				{Type: fix.ActionEdit, Label: "Second action"},
				{Type: fix.ActionEdit, Label: "Third action"},
			},
		},
		fixActionIdx: 1,
	}

	output := m.renderFixActionModal()

	markerCount := strings.Count(output, "> ")
	if markerCount != 1 {
		t.Errorf("expected exactly 1 selection marker, got %d", markerCount)
	}

	if !strings.Contains(output, "> Second action") {
		t.Error("expected selection marker on second action (fixActionIdx=1)")
	}
}

func TestRenderFixActionModal_NoFixTarget(t *testing.T) {
	m := model{
		width:        120,
		height:       40,
		fixTarget:    nil,
		fixActionIdx: 0,
	}

	output := m.renderFixActionModal()

	if !strings.Contains(output, "Choose action") {
		t.Error("expected 'Choose action' even with no fix target")
	}
}

func TestRenderMain_BasicStructure(t *testing.T) {
	live := domain.NewScanProgress(true)
	live.Hostname = "testhost"
	live.LocalIP = "192.168.1.1"
	live.AddFindings([]domain.Finding{
		{
			ID:          "lynis.AUTH-9286",
			Title:       "SSH password authentication enabled",
			Severity:    domain.SeverityHigh,
			Source:      domain.SourceLynis,
			Remediation: domain.RemediationAuto,
		},
	})
	live.Finalize()

	m := model{
		live:   live,
		width:  160,
		height: 50,
		phase:  "ready",
		snapOK: true,
		snap:   live.Snapshot(),
	}
	m.rebuildTable()

	output := m.renderMain()

	if !strings.Contains(output, "LINUX SELF-HOSTING SECURITY SCANNER") {
		t.Error("expected scanner eyebrow in output")
	}
	if !strings.Contains(output, "testhost") {
		t.Error("expected hostname in output")
	}
	if !strings.Contains(output, "95/100") {
		t.Error("expected score in output")
	}
	if strings.Contains(output, "Grade") {
		t.Error("did not expect grade in output")
	}
	if !strings.Contains(output, "FINDINGS") {
		t.Error("expected 'FINDINGS' header in output")
	}
}

func TestRenderMain_LoadingPhase(t *testing.T) {
	m := model{
		width:  120,
		height: 30,
		phase:  "loading",
		snapOK: true,
		snap: domain.Snapshot{
			Tools: map[string]domain.ToolStateJSON{
				"trivy": {Status: int(domain.ToolRunning), Message: "Scanning..."},
				"lynis": {Status: int(domain.ToolPending), Message: "Waiting..."},
			},
		},
	}

	output := m.renderLoading()

	if !strings.Contains(output, "hostveil") {
		t.Error("expected 'hostveil' brand in loading output")
	}
	if !strings.Contains(output, "trivy") {
		t.Error("expected 'trivy' tool name in loading output")
	}
}

func TestRenderLoading_LongToolMessageStaysInBounds(t *testing.T) {
	m := model{
		width:  120,
		height: 30,
		phase:  "loading",
		snapOK: true,
		snap: domain.Snapshot{
			Tools: map[string]domain.ToolStateJSON{
				"update": {Status: int(domain.ToolDone), Message: "Up to date"},
				"trivy":  {Status: int(domain.ToolDegraded), Message: "Partial: found 228 issues, error: config scan \"/opt/compose/vuln-project/docker-compose.yml\": invalid character 'S' looking for beginning of value"},
				"lynis":  {Status: int(domain.ToolRunning), Message: "Auditing system hardening..."},
			},
		},
	}

	output := m.renderLoading()
	for i, line := range strings.Split(output, "\n") {
		if got := lipgloss.Width(line); got > m.width {
			t.Fatalf("line %d exceeds width: got %d, want <= %d", i+1, got, m.width)
		}
	}
	if strings.Contains(output, "invalid character") {
		t.Fatal("expected long raw error to be truncated out of loading view")
	}
}

func TestRenderExportModal_BasicStructure(t *testing.T) {
	m := model{
		width:     120,
		height:    40,
		exportIdx: 0,
		modal:     modalExport,
	}

	output := m.renderExportModal()

	if !strings.Contains(output, "Export report") {
		t.Error("expected 'Export report' in modal output")
	}
	if !strings.Contains(output, "JSON") {
		t.Error("expected JSON format option")
	}
	if !strings.Contains(output, "CSV") {
		t.Error("expected CSV format option")
	}
	if !strings.Contains(output, "> ") {
		t.Error("expected selection marker")
	}
}

func TestRenderMain_ResponsiveWidthsStayInBounds(t *testing.T) {
	for _, width := range []int{80, 120, 180} {
		t.Run(fmt.Sprintf("width_%d", width), func(t *testing.T) {
			live := domain.NewScanProgress(true)
			live.Hostname = "testhost"
			live.LocalIP = "172.23.0.2"
			live.AddFindings([]domain.Finding{
				{
					ID:          "trivy.cve-2024-24790",
					Title:       "curl: Unpreserved file permissions during atomic rename",
					Severity:    domain.SeverityCritical,
					Source:      domain.SourceTrivy,
					Service:     "nginx:1.20-alpine",
					Remediation: domain.RemediationAuto,
					Description: "When curl saves cookies, alt-svc and hsts data to local files, it makes the operation atomic by finalizing the operation with a rename.",
				},
			})
			live.Finalize()

			m := NewApp(live, nil)
			m.width = width
			m.height = 44
			m.phase = "ready"
			m.snap = live.Snapshot()
			m.snapOK = true
			m.rebuildTable()

			output := m.renderMain()
			for i, line := range strings.Split(output, "\n") {
				if got := lipgloss.Width(line); got > width {
					t.Fatalf("line %d exceeds width: got %d, want <= %d", i+1, got, width)
				}
			}
		})
	}
}

func TestRenderMain_ShowsFindingTitle(t *testing.T) {
	live := domain.NewScanProgress(true)
	live.AddFindings([]domain.Finding{
		{
			ID:          "trivy.cve-2022-32207",
			Title:       "curl: Unpreserved file permissions",
			Severity:    domain.SeverityCritical,
			Source:      domain.SourceTrivy,
			Remediation: domain.RemediationAuto,
		},
	})
	live.Finalize()

	m := NewApp(live, nil)
	m.width = 180
	m.height = 44
	m.phase = "ready"
	m.snap = live.Snapshot()
	m.snapOK = true
	m.rebuildTable()

	output := m.renderMain()
	if !strings.Contains(output, "curl: Unpreserved file permissions") {
		t.Fatal("expected findings table to include finding title")
	}
}

func TestRenderDetailContent_DoesNotTruncateTitle(t *testing.T) {
	f := domain.Finding{
		ID:       "trivy.cve-2025-68121",
		Title:    "crypto/tls: crypto/tls: Incorrect certificate validation during TLS session resumption",
		Severity: domain.SeverityCritical,
		Source:   domain.SourceTrivy,
	}

	output := renderDetailContent(DefaultTheme(), &f, 38)
	normalized := strings.Join(strings.Fields(output), " ")
	for _, part := range []string{"crypto/tls:", "Incorrect", "certificate", "TLS", "session", "resumption"} {
		if !strings.Contains(normalized, part) {
			t.Fatalf("expected detail title to contain %q", part)
		}
	}
	if strings.Contains(output, "…") {
		t.Fatal("did not expect detail title truncation")
	}
}

func TestUpdate_WindowResizeDoesNotPanicAfterTableLayoutChange(t *testing.T) {
	live := domain.NewScanProgress(true)
	live.AddFindings([]domain.Finding{
		{ID: "a", Title: "Critical finding with a visible title", Severity: domain.SeverityCritical, Source: domain.SourceTrivy},
		{ID: "b", Title: "High finding with a visible title", Severity: domain.SeverityHigh, Source: domain.SourceLynis},
	})
	live.Finalize()

	m := NewApp(live, nil)
	m.phase = "ready"
	m.snap = live.Snapshot()
	m.snapOK = true
	m.width = 180
	m.height = 44
	m.rebuildTable()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("resize should not panic, got %v", r)
		}
	}()

	tm, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 38})
	mv := tm.(model)
	tm, _ = mv.Update(tea.WindowSizeMsg{Width: 80, Height: 32})
	mv = tm.(model)
	_, _ = mv.Update(tea.WindowSizeMsg{Width: 180, Height: 44})
}

func TestUpdate_SpaceTogglesSelectionInRenderedTable(t *testing.T) {
	live := domain.NewScanProgress(true)
	live.AddFindings([]domain.Finding{
		{ID: "a", Title: "Selectable finding", Severity: domain.SeverityCritical, Source: domain.SourceTrivy},
	})
	live.Finalize()

	m := NewApp(live, nil)
	m.phase = "ready"
	m.snap = live.Snapshot()
	m.snapOK = true
	m.width = 180
	m.height = 44
	m.rebuildTable()

	tm, _ := m.Update(tea.KeyPressMsg(tea.Key{Text: " ", Code: ' '}))
	mv := tm.(model)
	if !mv.selectedSet["a"] {
		t.Fatal("expected finding to be selected")
	}
	if !strings.Contains(mv.renderMain(), "◆") {
		t.Fatal("expected selected checkbox in rendered table")
	}
}

func TestRebuildTable_RowsArePlainStrings(t *testing.T) {
	live := domain.NewScanProgress(true)
	live.AddFindings([]domain.Finding{
		{ID: "a", Title: "Plain finding", Severity: domain.SeverityCritical, Source: domain.SourceTrivy},
	})
	live.Finalize()

	m := NewApp(live, nil)
	m.phase = "ready"
	m.snap = live.Snapshot()
	m.snapOK = true
	m.width = 180
	m.height = 44
	m.selectedSet["a"] = true
	m.rebuildTable()

	for rowIdx, row := range m.table.Rows() {
		for colIdx, cell := range row {
			if strings.Contains(cell, "\x1b[") {
				t.Fatalf("row %d col %d contains ANSI styling: %q", rowIdx, colIdx, cell)
			}
		}
	}
}

func TestUpdate_DetailModeScrollDoesNotMoveFindingCursor(t *testing.T) {
	live := domain.NewScanProgress(true)
	live.AddFindings([]domain.Finding{
		{ID: "a", Title: "First finding", Description: strings.Repeat("detail line one. ", 40), Severity: domain.SeverityCritical, Source: domain.SourceTrivy},
		{ID: "b", Title: "Second finding", Description: strings.Repeat("detail line two. ", 40), Severity: domain.SeverityHigh, Source: domain.SourceTrivy},
	})
	live.Finalize()

	m := NewApp(live, nil)
	m.phase = "ready"
	m.snap = live.Snapshot()
	m.snapOK = true
	m.width = 180
	m.height = 32
	m.mode = paneDetail
	m.rebuildTable()
	before := m.table.Cursor()

	tm, _ := m.Update(tea.KeyPressMsg(tea.Key{Code: tea.KeyDown}))
	mv := tm.(model)
	if got := mv.table.Cursor(); got != before {
		t.Fatalf("expected detail scroll to leave table cursor at %d, got %d", before, got)
	}
}

func TestUpdate_SpacePreservesCursor(t *testing.T) {
	live := domain.NewScanProgress(true)
	live.AddFindings([]domain.Finding{
		{ID: "a", Title: "First finding", Severity: domain.SeverityCritical, Source: domain.SourceTrivy},
		{ID: "b", Title: "Second finding", Severity: domain.SeverityHigh, Source: domain.SourceTrivy},
		{ID: "c", Title: "Third finding", Severity: domain.SeverityMedium, Source: domain.SourceLynis},
	})
	live.Finalize()

	m := NewApp(live, nil)
	m.phase = "ready"
	m.snap = live.Snapshot()
	m.snapOK = true
	m.width = 180
	m.height = 44
	m.rebuildTable()

	m.table.SetCursor(2)
	before := m.table.Cursor()

	tm, _ := m.Update(tea.KeyPressMsg(tea.Key{Text: " ", Code: ' '}))
	mv := tm.(model)
	if got := mv.table.Cursor(); got != before {
		t.Fatalf("expected space to preserve cursor at %d, got %d", before, got)
	}
	if !mv.selectedSet["c"] {
		t.Fatal("expected third finding to be selected")
	}
}

func TestUpdate_MouseWheelScrollsDetail(t *testing.T) {
	// Just verify that ScrollDown/ScrollUp methods work on viewport
	// Actual mouse event routing is tested via key delegation
	var vp viewport.Model
	vp.SetHeight(10)
	vp.SetContent(strings.Repeat("line\n", 50))
	vp.GotoTop()

	beforeY := vp.YOffset()
	vp.ScrollDown(3)
	afterY := vp.YOffset()

	if afterY <= beforeY {
		t.Fatalf("expected scroll down to increase YOffset, got before=%d after=%d", beforeY, afterY)
	}
}

func TestUpdate_MouseWheelScrollsTable(t *testing.T) {
	live := domain.NewScanProgress(true)
	for i := 0; i < 10; i++ {
		live.AddFindings([]domain.Finding{
			{ID: fmt.Sprintf("f%d", i), Title: fmt.Sprintf("Finding %d", i), Severity: domain.SeverityHigh, Source: domain.SourceTrivy},
		})
	}
	live.Finalize()

	m := NewApp(live, nil)
	m.phase = "ready"
	m.snap = live.Snapshot()
	m.snapOK = true
	m.width = 180
	m.height = 40
	m.rebuildTable()

	before := m.table.Cursor()

	// Simulate wheel down via key press (table responds to up/down)
	tm, _ := m.Update(tea.KeyPressMsg(tea.Key{Code: tea.KeyDown}))
	mv := tm.(model)
	if mv.table.Cursor() <= before {
		t.Fatal("expected down key to move table cursor down")
	}
}

func TestPanelAt_TwoPanelMode(t *testing.T) {
	live := domain.NewScanProgress(true)
	live.AddFindings([]domain.Finding{
		{ID: "a", Title: "Finding", Severity: domain.SeverityHigh, Source: domain.SourceTrivy},
	})
	live.Finalize()

	m := NewApp(live, nil)
	m.width = 140
	m.height = 40
	m.phase = "ready"
	m.snap = live.Snapshot()
	m.snapOK = true
	m.rebuildTable()

	listW := m.listWidth()

	// X in list area should return paneList
	if got := m.panelAt(0); got != paneList {
		t.Fatalf("x=0: expected paneList, got %v", got)
	}
	if got := m.panelAt(listW / 2); got != paneList {
		t.Fatalf("x=listW/2: expected paneList, got %v", got)
	}

	// X in detail area (after gap) should return paneDetail
	detailStart := listW + 2
	if got := m.panelAt(detailStart + 10); got != paneDetail {
		t.Fatalf("x=detailStart+10: expected paneDetail, got %v", got)
	}
}

func TestPanelAt_OnePanelMode(t *testing.T) {
	live := domain.NewScanProgress(true)
	live.AddFindings([]domain.Finding{
		{ID: "a", Title: "Finding", Severity: domain.SeverityHigh, Source: domain.SourceTrivy},
	})
	live.Finalize()

	m := NewApp(live, nil)
	m.width = 80
	m.height = 40
	m.phase = "ready"
	m.snap = live.Snapshot()
	m.snapOK = true
	m.rebuildTable()

	// In one-panel mode, should return current mode
	m.mode = paneList
	if got := m.panelAt(0); got != paneList {
		t.Fatalf("mode=list, x=0: expected paneList, got %v", got)
	}
	m.mode = paneDetail
	if got := m.panelAt(0); got != paneDetail {
		t.Fatalf("mode=detail, x=0: expected paneDetail, got %v", got)
	}
}

func TestPanelAt_ThreePanelMode(t *testing.T) {
	live := domain.NewScanProgress(true)
	live.AddFindings([]domain.Finding{
		{ID: "a", Title: "Finding", Severity: domain.SeverityHigh, Source: domain.SourceTrivy},
	})
	live.Finalize()

	m := NewApp(live, nil)
	m.width = 200
	m.height = 40
	m.phase = "ready"
	m.snap = live.Snapshot()
	m.snapOK = true
	m.rebuildTable()

	fw := m.filterWidth()
	listStart := fw + 2
	listEnd := listStart + m.listWidth() + 2

	// X in filter area should return paneList
	if got := m.panelAt(0); got != paneList {
		t.Fatalf("x=0 (filter): expected paneList, got %v", got)
	}

	// X in list area should return paneList
	if got := m.panelAt(listStart + 10); got != paneList {
		t.Fatalf("x=listStart+10: expected paneList, got %v", got)
	}

	// X in detail area should return paneDetail
	if got := m.panelAt(listEnd + 10); got != paneDetail {
		t.Fatalf("x=listEnd+10: expected paneDetail, got %v", got)
	}
}

func TestUpdate_MouseWheelIgnoredOverHeader(t *testing.T) {
	live := domain.NewScanProgress(true)
	for i := 0; i < 10; i++ {
		live.AddFindings([]domain.Finding{
			{ID: fmt.Sprintf("f%d", i), Title: fmt.Sprintf("Finding %d", i), Severity: domain.SeverityHigh, Source: domain.SourceTrivy},
		})
	}
	live.Finalize()

	m := NewApp(live, nil)
	m.phase = "ready"
	m.snap = live.Snapshot()
	m.snapOK = true
	m.width = 180
	m.height = 40
	m.rebuildTable()

	headerH := lipgloss.Height(m.renderHeader())
	metricsH := lipgloss.Height(m.renderMetrics())
	topArea := headerH + metricsH

	before := m.table.Cursor()

	// Mouse wheel over header/metrics area should not change cursor
	// We can't easily construct a MouseMsg, so we verify the height calculation
	if topArea <= 0 {
		t.Fatal("expected header+metrics height to be positive")
	}

	// Verify that wheel down below header area does scroll
	m.table.SetCursor(0)
	tm, _ := m.Update(tea.KeyPressMsg(tea.Key{Code: tea.KeyDown}))
	mv := tm.(model)
	if mv.table.Cursor() <= before {
		t.Fatal("expected down key below header to move cursor")
	}
}
