package web

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

// The score series has been on disk since the store was written, and #603
// put ScoreHistory on the engine so both interfaces could draw it without
// reimplementing the shape. Neither did yet — this is that follow-up, and
// the point of it is that both draw from one implementation.
func TestTrendRouteServesTheSparklineTheTUIDraws(t *testing.T) {
	s, _ := testServer(t)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, err := authedClient(t, s, srv).Get(srv.URL + "/api/trend")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("/api/trend returned %d: %s", resp.StatusCode, body)
	}

	var payload struct {
		Points    []model.ScorePoint `json:"points"`
		Sparkline string             `json:"sparkline"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("payload is not the documented shape: %v\n%s", err, body)
	}
	// The glyphs must be exactly what model.Sparkline produces for those
	// points. If the handler ever renders them itself, this is the failure.
	if want := model.Sparkline(payload.Points); payload.Sparkline != want {
		t.Errorf("sparkline = %q, want %q — the route is not using model.Sparkline", payload.Sparkline, want)
	}
}

// A second bucketing rule in JavaScript is the shape that already cost this
// file its domain table. The page must render the glyphs the server sent.
func TestDashboardDoesNotBucketScoresItself(t *testing.T) {
	app, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(app)
	if strings.Contains(js, "▁") || strings.Contains(js, "▂") || strings.Contains(js, "█") {
		t.Error("app.js contains block glyphs; the sparkline must come from model.Sparkline via /api/trend")
	}
	if !strings.Contains(js, "trend.sparkline") {
		t.Error("app.js does not render the server-rendered sparkline")
	}
	if !strings.Contains(js, `"/api/trend"`) {
		t.Error("app.js never fetches /api/trend")
	}

	index, err := assets.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(index), `id="trend"`) {
		t.Error("index.html has no element for the trend to render into")
	}
}
