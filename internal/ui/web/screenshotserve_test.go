package web

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/seolcu/hostveil/internal/ui/theme"
	"github.com/seolcu/hostveil/internal/ui/uitest"
)

// TestScreenshotServe serves the dashboard over the published fixture so
// site/assets/web.png can be re-taken, and is a no-op in normal test runs.
//
// It is the counterpart to the TUI's TestSnapshotDump, and it exists for the
// same reason: the published picture has to be reproducible by whoever changes
// the interface next. The terminal frame can simply be re-rendered; a browser
// screenshot cannot, so the closest available thing is a dashboard serving a
// host that is written down instead of one somebody has to go and find.
//
// It replaces this repository's previous answer, which was to bring up the
// Vagrant demo VM — twenty minutes, several gigabytes of deliberately
// outdated images, and a host whose findings drift with every image rebuild.
// Nothing about the picture needed a real machine; it needed a real *page*.
//
// The page is real: every route, asset, generated stylesheet and token comes
// from Server.Handler, exactly as `hostveil serve` builds it. Only /api/result
// is substituted, and it is the one thing that has to be, since an engine
// produces the report of whatever host it is on. That substitution is also the
// one divergence worth knowing about — the override sits in front of the
// guard, so this instance answers /api/result without the token. Localhost,
// for the length of one screenshot, and nothing else is relaxed.
//
//	HOSTVEIL_SCREENSHOT_ADDR=127.0.0.1:8788 go test ./internal/ui/web -run TestScreenshotServe
//	firefox --headless --no-remote --profile "$(mktemp -d)" \
//	        --window-size=1400,900 --screenshot site/assets/web.png \
//	        "$(the URL it prints)"
func TestScreenshotServe(t *testing.T) {
	addr := os.Getenv("HOSTVEIL_SCREENSHOT_ADDR")
	if addr == "" {
		t.Skip("set HOSTVEIL_SCREENSHOT_ADDR to serve the published fixture for a screenshot")
	}

	// Rebuilt on the defaults rather than reusing testServer's, which picks
	// a non-default theme and arrangement precisely so the tests do not
	// silently pass on them. The published picture has to show what a person
	// gets when they type `hostveil serve` and choose nothing.
	base, _ := testServer(t)
	s := New(base.engine, addr, theme.Default().ID, DefaultLayout().ID)
	real := s.Handler()
	rep := uitest.PublishedReport()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/result", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, resultPayload{Report: rep})
	})
	mux.Handle("/", real)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen on %s: %v", addr, err)
	}
	defer ln.Close() //nolint:errcheck // the process is going away

	fmt.Printf("\nscreenshot fixture at http://%s/?t=%s\n\n", ln.Addr(), s.token)

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	done := make(chan struct{})
	go func() {
		_ = srv.Serve(ln)
		close(done)
	}()

	// Bounded, because a test that waits for a signal is a test that hangs a
	// CI run if the env var ever leaks into one. Long enough for a headless
	// browser to start, load, and paint.
	select {
	case <-time.After(screenshotServeFor()):
	case <-done:
	}
	_ = srv.Close()
}

// screenshotServeFor is how long the fixture stays up, overridable for a slow
// browser start.
func screenshotServeFor() time.Duration {
	if v := os.Getenv("HOSTVEIL_SCREENSHOT_SECONDS"); v != "" {
		if d, err := time.ParseDuration(v + "s"); err == nil {
			return d
		}
	}
	return 45 * time.Second
}
