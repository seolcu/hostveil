package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/seolcu/hostveil/internal/history"
	"github.com/seolcu/hostveil/internal/model"
)

// hostveil has kept and pruned the last 30 scan snapshots since the store
// was written, and nothing ever read more than the newest one: LastReport
// takes the last element, and every interface shows "since last scan" and
// nothing longer. That answers "did that round of fixes help?" and cannot
// answer "is this host getting better?" — with the data for it already on
// disk the whole time.

// saveScan writes a snapshot with a chosen score. The id carries the time,
// so the fixtures control ordering by naming their own.
func saveScan(t *testing.T, s *history.Store, id string, overall uint8, applicable bool) {
	t.Helper()
	data, err := json.Marshal(model.Report{
		Score: model.ScoreBreakdown{Overall: overall, Applicable: applicable},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveReport(id, data); err != nil {
		t.Fatal(err)
	}
}

func TestScoreHistoryReturnsEveryScanOldestFirst(t *testing.T) {
	dir := t.TempDir()
	store := history.NewStore(dir)
	e := New(Config{Store: store})

	// Deliberately saved out of order: the ids are timestamp-prefixed and
	// the listing sorts by them, so a store that returned directory order
	// would produce a chart running backwards.
	saveScan(t, store, "20260101-120000.000-c", 71, true)
	saveScan(t, store, "20260101-100000.000-a", 42, true)
	saveScan(t, store, "20260101-110000.000-b", 58, true)

	points, err := e.ScoreHistory()
	if err != nil {
		t.Fatal(err)
	}
	if len(points) != 3 {
		t.Fatalf("got %d points, want 3", len(points))
	}
	for i, want := range []uint8{42, 58, 71} {
		if points[i].Overall != want {
			t.Errorf("point %d = %d, want %d — the series is not oldest-first", i, points[i].Overall, want)
		}
	}
	if !points[0].At.Before(points[2].At) {
		t.Errorf("timestamps are not increasing: %v then %v", points[0].At, points[2].At)
	}
}

// A scan where every domain was skipped or failed has no score at all —
// ScoreBreakdown.Applicable is false and all three UIs render N/A. A trend
// that flattened that to 0 would draw a cliff where the truth is that
// nobody could look, which is the same lie the aggregate score already
// refuses to tell.
func TestScoreHistoryCarriesTheNotApplicableFlag(t *testing.T) {
	store := history.NewStore(t.TempDir())
	e := New(Config{Store: store})

	saveScan(t, store, "20260101-100000.000-a", 80, true)
	saveScan(t, store, "20260101-110000.000-b", 0, false)

	points, err := e.ScoreHistory()
	if err != nil {
		t.Fatal(err)
	}
	if len(points) != 2 {
		t.Fatalf("got %d points, want 2", len(points))
	}
	if !points[0].Applicable {
		t.Error("a scored scan came back as not applicable")
	}
	if points[1].Applicable {
		t.Error("an unscorable scan came back as applicable — it would be charted as a drop to 0")
	}
}

// One damaged snapshot costs that snapshot, not the series. This is a
// history view, and the same reasoning Store.List follows when it returns
// what it could read: a file that will not parse is one missing point, not
// a reason to refuse the other twenty-nine.
func TestScoreHistorySkipsUnreadableSnapshots(t *testing.T) {
	dir := t.TempDir()
	store := history.NewStore(dir)
	e := New(Config{Store: store})

	saveScan(t, store, "20260101-100000.000-a", 42, true)
	saveScan(t, store, "20260101-120000.000-c", 71, true)
	// A truncated snapshot, of the kind a crash mid-write used to leave.
	if err := os.WriteFile(filepath.Join(dir, "scans", "20260101-110000.000-b.json"),
		[]byte(`{"score":{"over`), 0o600); err != nil {
		t.Fatal(err)
	}
	// And one whose name carries no timestamp at all.
	if err := os.WriteFile(filepath.Join(dir, "scans", "not-a-scan.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}

	points, err := e.ScoreHistory()
	if err != nil {
		t.Fatalf("one bad snapshot failed the whole call: %v", err)
	}
	if len(points) != 2 {
		t.Fatalf("got %d points, want the 2 readable ones", len(points))
	}
	if points[0].Overall != 42 || points[1].Overall != 71 {
		t.Errorf("wrong points survived: %+v", points)
	}
}

// Nothing saved is not an error — it is a host that has not been scanned.
func TestScoreHistoryOnAFreshStateDirectory(t *testing.T) {
	e := New(Config{Store: history.NewStore(t.TempDir())})
	points, err := e.ScoreHistory()
	if err != nil {
		t.Fatalf("an empty store errored: %v", err)
	}
	if len(points) != 0 {
		t.Errorf("got %d points from an empty store", len(points))
	}
}

// The retention cap already applied to snapshots applies to the trend, by
// construction rather than by a second limit: the series is exactly what
// the store kept.
func TestScoreHistoryIsBoundedByRetention(t *testing.T) {
	store := history.NewStore(t.TempDir())
	e := New(Config{Store: store})
	for i := range 40 {
		saveScan(t, store, "202601"+twoDigit(i/24+1)+"-"+twoDigit(i%24)+"0000.000-x", uint8(i), true)
	}
	points, err := e.ScoreHistory()
	if err != nil {
		t.Fatal(err)
	}
	if len(points) > 30 {
		t.Errorf("got %d points; the store keeps 30", len(points))
	}
}

func twoDigit(n int) string {
	if n < 10 {
		return "0" + string(rune('0'+n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}
