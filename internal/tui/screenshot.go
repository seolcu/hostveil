package tui

import (
	"github.com/seolcu/hostveil/internal/domain"
	"github.com/seolcu/hostveil/internal/fix"
)

// RenderScreenshot returns the alt-screen TUI render for a ready-state snapshot
// at the given terminal size. It is intended for docs and visual regression exports.
func RenderScreenshot(app *model, width, height int) string {
	m := *app
	m.phase = "ready"
	m.snap = m.live.Snapshot()
	m.snapOK = true
	m.width = width
	m.height = height
	m.rebuildTable()
	return m.View().Content
}

// NewReadyApp builds an app model in the ready phase using the given snapshot data.
func NewReadyApp(live *domain.ScanProgress, reg *fix.Registry) *model {
	m := NewApp(live, reg)
	m.phase = "ready"
	m.snap = live.Snapshot()
	m.snapOK = true
	return m
}
