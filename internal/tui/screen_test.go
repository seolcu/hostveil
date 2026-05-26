package tui

import (
	"strings"
	"testing"

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
