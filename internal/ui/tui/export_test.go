package tui

import (
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/core"
	"github.com/seolcu/hostveil/internal/history"
)

func exportModel(t *testing.T, w, h int) *appModel {
	t.Helper()
	r := sampleReport()
	m := &appModel{
		mode: modeList, width: w, height: h, report: r, selected: map[string]bool{},
		engine: core.New(core.Config{Version: "v-test", Store: history.NewStore(t.TempDir())}),
	}
	m.active = m.report.Select(m.filter)
	return m
}

func TestExportPickerOpensAndListsFormats(t *testing.T) {
	m := exportModel(t, 120, 34)
	m.openExportPicker()
	if m.mode != modeExport || m.exportCursor != 0 {
		t.Fatalf("picker opened in mode %v at cursor %d", m.mode, m.exportCursor)
	}
	got := plain(m.View().Content)
	for _, want := range []string{"Markdown", "JSON", "SARIF", "Word", "PDF"} {
		if !strings.Contains(got, want) {
			t.Errorf("export picker does not list %q:\n%s", want, got)
		}
	}
}

func TestExportPickerEscReturnsToThePreviousMode(t *testing.T) {
	m := exportModel(t, 120, 34)
	m.mode = modeDetail
	m.openExportPicker()
	if m.exportPrev != modeDetail {
		t.Fatalf("exportPrev = %v, want modeDetail", m.exportPrev)
	}
	m.keyExport("esc")
	if m.mode != modeDetail {
		t.Errorf("esc left mode %v, want modeDetail", m.mode)
	}
}

func TestExportPickerEnterCarriesTheFormatIntoThePathScreen(t *testing.T) {
	m := exportModel(t, 120, 34)
	m.openExportPicker()
	m.keyExport("down") // sarif
	m.keyExport("enter")

	if m.mode != modeExportPath {
		t.Fatalf("mode = %v, want modeExportPath", m.mode)
	}
	want := core.ExportFormats()[1]
	if m.exportFormat != want.ID {
		t.Errorf("exportFormat = %q, want %q", m.exportFormat, want.ID)
	}
	if !strings.HasSuffix(string(m.exportPath), "."+want.Ext) {
		t.Errorf("prefilled path %q does not end in .%s", string(m.exportPath), want.Ext)
	}
	if m.exportPathCursor != len(m.exportPath) {
		t.Errorf("cursor = %d, want it at the end of the prefilled path (%d)", m.exportPathCursor, len(m.exportPath))
	}
}

func TestExportPathEditing(t *testing.T) {
	m := exportModel(t, 120, 34)
	m.exportPath, m.exportPathCursor = []rune("report.md"), 9

	m.keyExportPath("backspace")
	if string(m.exportPath) != "report.m" {
		t.Fatalf("after backspace: %q", string(m.exportPath))
	}

	m.exportPathCursor = 0
	m.keyExportPath("x")
	if string(m.exportPath) != "xreport.m" || m.exportPathCursor != 1 {
		t.Fatalf("after inserting at cursor 0: %q cursor=%d", string(m.exportPath), m.exportPathCursor)
	}

	m.exportPathCursor = len(m.exportPath)
	m.keyExportPath("left")
	m.keyExportPath("left")
	if m.exportPathCursor != len(m.exportPath)-2 {
		t.Errorf("left/left cursor = %d, want %d", m.exportPathCursor, len(m.exportPath)-2)
	}
	m.keyExportPath("end")
	if m.exportPathCursor != len(m.exportPath) {
		t.Errorf("end cursor = %d, want %d", m.exportPathCursor, len(m.exportPath))
	}
	m.keyExportPath("home")
	if m.exportPathCursor != 0 {
		t.Errorf("home cursor = %d, want 0", m.exportPathCursor)
	}
}

func TestExportPathEnterRefusesAnEmptyPath(t *testing.T) {
	m := exportModel(t, 120, 34)
	m.mode = modeExportPath
	m.exportPath, m.exportPathCursor = nil, 0
	m.keyExportPath("enter")
	if m.mode != modeExportPath {
		t.Errorf("an empty path should not leave modeExportPath, got %v", m.mode)
	}
}

func TestExportPathEnterStartsTheExport(t *testing.T) {
	m := exportModel(t, 120, 34)
	m.exportFormat = "markdown"
	m.exportPath, m.exportPathCursor = []rune("out.md"), 6

	_, cmd := m.keyExportPath("enter")
	if m.mode != modeApplying {
		t.Fatalf("mode = %v, want modeApplying", m.mode)
	}
	if cmd == nil {
		t.Fatal("enter should return a command that performs the export")
	}

	var saved string
	var savedData []byte
	m.saveExport = func(format, path string, data []byte) error {
		saved = format + "|" + path
		savedData = data
		return nil
	}
	// Rebuild the command now that saveExport is wired, mirroring how New()
	// would have set it before the key was ever pressed.
	_, cmd = m.keyExportPath("enter")
	msg := applyMsg(cmd)
	exp, ok := msg.(exportedMsg)
	if !ok {
		t.Fatalf("command returned %T, want exportedMsg", msg)
	}
	if exp.err != nil {
		t.Fatalf("export failed: %v", exp.err)
	}
	if saved != "markdown|out.md" {
		t.Errorf("saveExport called with %q, want \"markdown|out.md\"", saved)
	}
	if len(savedData) == 0 || !strings.Contains(string(savedData), "hostveil security report") {
		t.Errorf("saved data does not look like the Markdown report:\n%s", savedData)
	}
}

func TestExportPathEscReturnsToThePicker(t *testing.T) {
	m := exportModel(t, 120, 34)
	m.mode = modeExportPath
	m.keyExportPath("esc")
	if m.mode != modeExport {
		t.Errorf("esc left mode %v, want modeExport", m.mode)
	}
}

func TestTheFooterNamesTheExportKey(t *testing.T) {
	if !strings.Contains(listHint, "e export") {
		t.Error("the list footer does not name the export key")
	}
	if !strings.Contains(emptyListHint, "e export") {
		t.Error("export must be reachable on a clean report too, so the empty-list footer names it as well")
	}
}
