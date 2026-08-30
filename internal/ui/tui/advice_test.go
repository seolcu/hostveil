package tui

import (
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/core"
	"github.com/seolcu/hostveil/internal/history"
)

func adviceModel(t *testing.T, w, h int) *appModel {
	t.Helper()
	r := sampleReport()
	m := &appModel{
		mode: modeList, width: w, height: h, report: r, selected: map[string]bool{},
		engine: core.New(core.Config{Version: "v-test", Store: history.NewStore(t.TempDir())}),
	}
	m.active = m.report.Select(m.filter)
	return m
}

func TestAdvicePickerOpensBusyAndListsTheFixableFinding(t *testing.T) {
	m := adviceModel(t, 120, 34)
	cmd := m.openAdvicePicker()
	if m.mode != modeAdvice || !m.adviceBusy {
		t.Fatalf("picker opened in mode %v busy=%v, want modeAdvice busy=true", m.mode, m.adviceBusy)
	}
	if cmd == nil {
		t.Fatal("opening the picker should return a command that runs Advise")
	}

	got0 := cmd()
	adv, ok := got0.(advisedMsg)
	if !ok {
		t.Fatalf("command returned %T, want advisedMsg", got0)
	}
	m2 := send(m, adv).(*appModel)
	got := strings.Join(strings.Fields(plain(m2.View().Content)), " ")
	if !strings.Contains(got, "Datastore exposed") {
		t.Errorf("advice screen does not list the fixable finding:\n%s", got)
	}
	if strings.Contains(got, "Privileged mode") {
		t.Errorf("advice screen lists the Manual finding, which has no fix to weigh:\n%s", got)
	}
}

func TestAdvicePickerEscReturnsToTheList(t *testing.T) {
	m := adviceModel(t, 120, 34)
	m.openAdvicePicker()
	m.keyAdvice("esc")
	if m.mode != modeList {
		t.Errorf("esc left mode %v, want modeList", m.mode)
	}
}

func TestAIContextEditorPrefillsFromTheSavedDescription(t *testing.T) {
	m := adviceModel(t, 120, 34)
	if err := m.engine.SetAIContext("a personal media server"); err != nil {
		t.Fatal(err)
	}
	m.openAdvicePicker()
	m.keyAdvice("c")
	if m.mode != modeAIContext {
		t.Fatalf("mode = %v, want modeAIContext", m.mode)
	}
	if string(m.aiContextText) != "a personal media server" {
		t.Errorf("aiContextText = %q, want the saved description", string(m.aiContextText))
	}
	if m.aiContextCursor != len(m.aiContextText) {
		t.Errorf("cursor = %d, want it at the end of the prefilled text (%d)", m.aiContextCursor, len(m.aiContextText))
	}
}

func TestAIContextEditorEscDiscardsAndReturnsToAdvice(t *testing.T) {
	m := adviceModel(t, 120, 34)
	m.openAdvicePicker()
	m.keyAdvice("c")
	m.keyAIContext("x")
	m.keyAIContext("esc")
	if m.mode != modeAdvice {
		t.Errorf("esc left mode %v, want modeAdvice", m.mode)
	}
	if m.engine.AIContext() != "" {
		t.Errorf("esc must not persist the edit, but AIContext() = %q", m.engine.AIContext())
	}
}

func TestAIContextEditorEnterSavesAndRestartsAdvise(t *testing.T) {
	m := adviceModel(t, 120, 34)
	m.openAdvicePicker()
	m.keyAdvice("c")
	for _, r := range "a stable production box" {
		m.keyAIContext(string(r))
	}
	_, cmd := m.keyAIContext("enter")

	if m.mode != modeAdvice {
		t.Fatalf("mode = %v, want modeAdvice", m.mode)
	}
	if got := m.engine.AIContext(); got != "a stable production box" {
		t.Fatalf("AIContext() = %q, want the saved text", got)
	}
	if m.aiContext != "a stable production box" {
		t.Errorf("cached aiContext = %q, want it refreshed for the render", m.aiContext)
	}
	if cmd == nil {
		t.Fatal("saving should re-fire the advise command against the new context")
	}
}

func TestTheFooterNamesTheAdviseKey(t *testing.T) {
	if !strings.Contains(listHint, "v advise") {
		t.Error("the list footer does not name the advise key")
	}
}
