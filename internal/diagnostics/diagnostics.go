// Package diagnostics records what a crash looked like, entirely on disk and
// entirely local. It has no network client and imports nothing that has one
// — that is the point of it: a panic anywhere in hostveil leaves a record
// here, and nothing here, nor `hostveil diagnostics` (cmd/hostveil) which
// reads these back, ever sends that record anywhere. Packaging it for a bug
// report and mailing it off are different acts, and this package and the
// command that reads it only ever do the first — the operator pastes the
// result into an issue by hand.
//
// A dependency-free leaf package on purpose, so internal/check and
// internal/core (which the panics actually happen in) and cmd/hostveil (which
// packages them) can all call it without creating an import cycle or
// widening the UI-layering allowlist in internal/ui/{tui,web}.
package diagnostics

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"
)

// CrashRecord is what one panic looked like. It never carries command
// stdout, finding evidence, or file contents — the same boundary
// platform.TraceRunner already draws for HOSTVEIL_DEBUG, and for the same
// reason: a record an operator might paste into a public issue must not be
// able to leak a credential it never needed to hold.
type CrashRecord struct {
	At      time.Time `json:"at"`
	Version string    `json:"version"`
	Go      string    `json:"go"`
	OS      string    `json:"os"`
	Arch    string    `json:"arch"`
	Command string    `json:"command"` // the hostveil subcommand that was running, e.g. "scan"
	Where   string    `json:"where"`   // what was happening: "checker ssh", "fix compose.ds016", "cli"
	Panic   string    `json:"panic"`
	Stack   string    `json:"stack"`
}

// NewRecord builds a CrashRecord from the running process's own identity and
// a panic that was just recovered.
//
// stack must be captured by the caller, with debug.Stack() called directly
// inside the recover — not passed through another function first — so it
// names the frames that actually panicked rather than this one.
func NewRecord(version, command, where string, panicValue any, stack []byte) CrashRecord {
	return CrashRecord{
		At:      time.Now(),
		Version: version,
		Go:      runtime.Version(),
		OS:      runtime.GOOS,
		Arch:    runtime.GOARCH,
		Command: command,
		Where:   where,
		Panic:   fmt.Sprintf("%v", panicValue),
		Stack:   string(stack),
	}
}

// maxRecords caps how many crash records are kept, the same way
// internal/history caps checkpoints — these are diagnostic exhaust, not
// backups, so there is no minimum-retention rule to go with the count.
const maxRecords = 20

func crashesDir(dir string) string { return filepath.Join(dir, "diagnostics", "crashes") }

// RecordCrash writes one crash record under dir and prunes older ones beyond
// maxRecords. dir is the hostveil state directory — history.DefaultDir() in
// production, or whatever a test points a Store at; this package has no
// opinion of its own about where that is.
//
// Every error here is swallowed. This runs from inside a recover, already
// mid-panic-report, and a failure to write a diagnostic file must never
// become the reason the friendly crash message never gets printed.
func RecordCrash(dir string, rec CrashRecord) {
	cdir := crashesDir(dir)
	if err := os.MkdirAll(cdir, 0o700); err != nil {
		return
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return
	}
	name := rec.At.UTC().Format("20060102-150405.000000") + ".json"
	if err := os.WriteFile(filepath.Join(cdir, name), data, 0o600); err != nil {
		return
	}
	prune(cdir)
}

func prune(dir string) {
	names := jsonFiles(dir)
	if len(names) <= maxRecords {
		return
	}
	sort.Strings(names) // filenames are timestamp-prefixed
	for _, name := range names[:len(names)-maxRecords] {
		_ = os.Remove(filepath.Join(dir, name))
	}
}

func jsonFiles(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			names = append(names, e.Name())
		}
	}
	return names
}

// Crashes returns up to limit of the most recent crash records, newest
// first. limit <= 0 means no limit.
func Crashes(dir string, limit int) ([]CrashRecord, error) {
	cdir := crashesDir(dir)
	names := jsonFiles(cdir)
	if names == nil {
		if _, err := os.Stat(cdir); err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		return nil, nil
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	if limit > 0 && len(names) > limit {
		names = names[:limit]
	}
	out := make([]CrashRecord, 0, len(names))
	for _, name := range names {
		// G304: a filename this package generated (a timestamp plus ".json"),
		// read back from the directory it wrote it into.
		//nolint:gosec // G304: this package's own crash record, in its own directory
		data, err := os.ReadFile(filepath.Join(cdir, name))
		if err != nil {
			continue
		}
		var rec CrashRecord
		if json.Unmarshal(data, &rec) != nil {
			continue
		}
		out = append(out, rec)
	}
	return out, nil
}
