package log

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
)

func TestNew_JSONShape(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf, "test-component")
	logger.Info("hello", "key", "value")

	line := buf.String()
	if line == "" {
		t.Fatal("logger produced no output")
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(line[:len(line)-1]), &got); err != nil {
		t.Fatalf("logger output is not valid JSON: %v\nline: %q", err, line)
	}
	if got["component"] != "test-component" {
		t.Errorf("component = %v, want test-component", got["component"])
	}
	if got["msg"] != "hello" {
		t.Errorf("msg = %v, want hello", got["msg"])
	}
	if got["key"] != "value" {
		t.Errorf("key = %v, want value", got["key"])
	}
	if got["time"] == nil {
		t.Errorf("time field missing")
	}
	if got["level"] != "INFO" {
		t.Errorf("level = %v, want INFO", got["level"])
	}
}

func TestNew_ScanRunIDFromContext(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf, "scan")
	ctx := WithScanRunID(context.Background(), "scan-abc-123")
	logger.InfoContext(ctx, "scanning")

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v\nline: %q", err, buf.String())
	}
	if got["scan_run_id"] != "scan-abc-123" {
		t.Errorf("scan_run_id = %v, want scan-abc-123", got["scan_run_id"])
	}
}

func TestNew_NoScanRunIDWhenContextAbsent(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf, "scan")
	logger.InfoContext(context.Background(), "scanning")

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v\nline: %q", err, buf.String())
	}
	if _, ok := got["scan_run_id"]; ok {
		t.Errorf("scan_run_id should be absent when context carries no id; got %v", got["scan_run_id"])
	}
}

func TestNew_LevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	h := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	logger := slog.New(&componentHandler{Handler: h, component: "x"})
	logger.Info("should-be-dropped")
	logger.Warn("should-appear")
	if !bytes.Contains(buf.Bytes(), []byte("should-appear")) {
		t.Errorf("warn-level line missing: %q", buf.String())
	}
	if bytes.Contains(buf.Bytes(), []byte("should-be-dropped")) {
		t.Errorf("info-level line leaked past warn filter: %q", buf.String())
	}
}
