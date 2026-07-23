package tui

import (
	"context"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/seolcu/hostveil/internal/ui/theme"
)

func key(s string) tea.KeyPressMsg { return tea.KeyPressMsg(tea.Key{Text: s}) }

// Every theme must render every mode. A palette with a role the styles
// builder does not read, or reads under the wrong name, shows up here rather
// than on a user's terminal.
func TestEveryThemeRendersEveryMode(t *testing.T) {
	for _, th := range theme.All() {
		for _, mode := range []mode{modeScanning, modeList, modeDetail, modeMessage, modeTheme} {
			m := &appModel{
				mode: mode, width: 100, height: 40, th: th,
				report: sampleReport(), selected: map[string]bool{}, status: "Scanning…",
			}
			m.rebuildActive()
			if got := m.View().Content; got == "" {
				t.Errorf("theme %s mode %v rendered nothing", th.ID, mode)
			}
		}
	}
}

// An appModel built as a bare literal — which is how every layout test and
// several call sites build one — must still render in the default theme
// rather than in no colors at all.
func TestZeroValueThemeIsTheDefault(t *testing.T) {
	m := &appModel{mode: modeList, width: 80, height: 24}
	if m.View().Content == "" {
		t.Fatal("a zero-value model rendered nothing")
	}
	if m.th.ID != theme.Default().ID {
		t.Errorf("zero-value theme resolved to %q, want %q", m.th.ID, theme.Default().ID)
	}
}

// The picker previews live: moving the cursor must restyle the interface, and
// cancelling must put back exactly what was there before.
func TestThemePickerPreviewAndCancel(t *testing.T) {
	m := tea.Model(&appModel{mode: modeList, width: 100, height: 40, selected: map[string]bool{}})
	m = send(m, scannedMsg{report: sampleReport()})

	m = send(m, key("t"))
	am := m.(*appModel)
	if am.mode != modeTheme {
		t.Fatalf("t did not open the theme picker, mode = %v", am.mode)
	}
	before := am.th.ID

	m = send(m, key("j"))
	am = m.(*appModel)
	if am.th.ID == before {
		t.Error("moving the cursor did not apply the theme under it")
	}
	if !strings.Contains(am.View().Content, theme.All()[am.themeCursor].Name) {
		t.Error("the picker does not name the theme it is previewing")
	}
	moved := am.th.ID

	m = send(m, tea.KeyPressMsg(tea.Key{Code: tea.KeyEsc}))
	am = m.(*appModel)
	if am.mode != modeList {
		t.Errorf("esc left the picker in mode %v", am.mode)
	}
	if am.th.ID != before {
		t.Errorf("esc kept the previewed theme %q instead of restoring %q", moved, before)
	}
}

// Keeping a theme persists it, so the next run starts in it. That is the
// whole point of the picker over a flag.
func TestThemePickerKeepSaves(t *testing.T) {
	var saved string
	m := tea.Model(&appModel{
		mode: modeList, width: 100, height: 40, selected: map[string]bool{},
		saveTheme: func(id string) error { saved = id; return nil },
	})
	m = send(m, scannedMsg{report: sampleReport()})
	m = send(m, key("t"))
	m = send(m, key("j"))
	m = send(m, tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))

	am := m.(*appModel)
	if am.mode != modeList {
		t.Errorf("enter left the picker in mode %v", am.mode)
	}
	if saved != am.th.ID || saved == "" {
		t.Errorf("saved %q, active theme is %q", saved, am.th.ID)
	}
}

// A preference that cannot be written down is not worth interrupting anyone
// over: the theme still applies for the rest of the session.
func TestThemePickerSurvivesASaveFailure(t *testing.T) {
	m := tea.Model(&appModel{
		mode: modeList, width: 100, height: 40, selected: map[string]bool{},
		saveTheme: func(string) error { return errWrite },
	})
	m = send(m, scannedMsg{report: sampleReport()})
	m = send(m, key("t"))
	m = send(m, key("j"))
	chosen := m.(*appModel).th.ID
	m = send(m, tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))

	am := m.(*appModel)
	if am.mode != modeList {
		t.Errorf("a failed save left the UI in mode %v", am.mode)
	}
	if am.th.ID != chosen {
		t.Errorf("a failed save discarded the chosen theme: %q, want %q", am.th.ID, chosen)
	}
}

// The picker opens on the theme already in use, not at the top of the list —
// otherwise the first arrow key moves away from where the user thinks they
// are.
func TestThemePickerOpensOnTheActiveTheme(t *testing.T) {
	all := theme.All()
	want := all[len(all)-1]
	m := &appModel{mode: modeList, width: 100, height: 40, th: want}
	m.openThemePicker()
	if got := all[m.themeCursor].ID; got != want.ID {
		t.Errorf("picker opened on %q, want %q", got, want.ID)
	}
}

// New must carry the resolved theme through, or --theme and the remembered
// preference would both be ignored the moment the TUI starts.
func TestNewAppliesTheGivenTheme(t *testing.T) {
	want, _ := theme.Lookup("tokyonight")
	m := New(context.Background(), nil, ThemeOpts{Initial: want}).(*appModel)
	if m.th.ID != want.ID {
		t.Errorf("New used theme %q, want %q", m.th.ID, want.ID)
	}
}

var errWrite = errWriteType{}

type errWriteType struct{}

func (errWriteType) Error() string { return "read-only state directory" }
