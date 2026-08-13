package tui

import (
	"testing"

	"github.com/seolcu/hostveil/internal/ui/uitest"
)

// TestUIStaysThin enforces the architectural boundary that keeps the UI a
// thin shell: production TUI code may import only the engine (core) and
// value types (model), never the fix, history, check, or compose packages
// directly. Reaching into those is exactly how hostveil v2 ended up with fix
// logic duplicated across its UIs.
//
// The check itself lives in internal/ui/uitest because the dashboard needs
// the identical one, and it used to be the identical one — the same twenty
// lines and the same list of four packages, written out twice. A fifth
// package added to one copy would have left the other half of the boundary
// open, with nothing anywhere to notice.
func TestUIStaysThin(t *testing.T) { uitest.AssertThinUI(t) }
