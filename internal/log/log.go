// Package log configures the structured logger used across hostveil.
// All log lines are JSON-encoded (one object per line) and carry a
// timestamp, severity, source component, and (when available) a
// correlation id.
package log

import (
	"context"
	"io"
	"log/slog"
	"os"
)

type ctxKey struct{}

// WithScanRunID returns a context carrying the scan_run_id that
// every log line emitted under that context inherits as the
// scan_run_id field.
func WithScanRunID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// scanRunIDFromContext extracts the scan_run_id, returning "" when
// absent.
func scanRunIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxKey{}).(string)
	return v
}

// New returns a JSON slog.Logger that writes to w. component is the
// emitting package's short name (e.g. "scan", "fix", "tui") and is
// attached to every log line.
func New(w io.Writer, component string) *slog.Logger {
	if w == nil {
		w = os.Stderr
	}
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo})
	return slog.New(&componentHandler{Handler: h, component: component})
}

// componentHandler attaches a static "component" field and, when the
// context carries a scan_run_id, attaches a "scan_run_id" field.
type componentHandler struct {
	slog.Handler
	component string
}

func (h *componentHandler) Handle(ctx context.Context, r slog.Record) error {
	r = r.Clone()
	r.AddAttrs(slog.String("component", h.component))
	if id := scanRunIDFromContext(ctx); id != "" {
		r.AddAttrs(slog.String("scan_run_id", id))
	}
	return h.Handler.Handle(ctx, r)
}

func (h *componentHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	inner := h.Handler.WithAttrs(attrs)
	return &componentHandler{Handler: inner, component: h.component}
}

func (h *componentHandler) WithGroup(name string) slog.Handler {
	inner := h.Handler.WithGroup(name)
	return &componentHandler{Handler: inner, component: h.component}
}
