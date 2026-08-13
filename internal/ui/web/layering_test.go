package web

import (
	"testing"

	"github.com/seolcu/hostveil/internal/ui/uitest"
)

// The dashboard is held to the same boundary as the TUI, by the same code.
// See internal/ui/uitest.AssertThinUI, and internal/ui/tui/layering_test.go
// for why it is not written out here as well.
func TestUIStaysThin(t *testing.T) { uitest.AssertThinUI(t) }
