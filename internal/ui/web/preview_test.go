package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// /api/preview had no test at all before Benefit was added beside Warning,
// so this is the first to pin ActionPreview's actual JSON shape rather than
// just the route's existence.
func TestPreviewCarriesBenefitAlongsideWarning(t *testing.T) {
	s, _ := testServer(t)
	rec := httptest.NewRecorder()
	req := authed(s, httptest.NewRequest(http.MethodGet, "/api/preview?id=compose.ds018&service=cache", nil))
	req.Host = "127.0.0.1:8787"
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	var preview struct {
		Actions []struct {
			Benefit string `json:"benefit"`
			Warning string `json:"warning"`
		} `json:"actions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &preview); err != nil {
		t.Fatal(err)
	}
	if len(preview.Actions) == 0 {
		t.Fatal("no actions in the preview")
	}
	if preview.Actions[0].Benefit == "" {
		t.Error("action 0 carries no benefit — every registered fix must state one")
	}
}
