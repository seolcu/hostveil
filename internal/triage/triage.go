// Package triage answers the question the rest of hostveil cannot: has this
// host already been broken into?
//
// It is a live-response collector and a first-pass analyst in one, built
// for an operator who is not an incident responder. It never changes the
// host. It writes one directory, the evidence bundle, and everything it
// concludes is computed from that bundle alone, so the same conclusions can
// be re-derived later, on another machine, by someone who does not trust the
// host or this run.
//
// # Order of collection
//
// Evidence is gathered in the order RFC 3227 calls the order of volatility:
// what disappears first is read first. Running processes and sockets, then
// the files that make something survive a reboot, then the logs. Each
// artifact is hashed as it is written and recorded in manifest.json with the
// command or path it came from, so the bundle carries its own chain of
// custody; `hostveil triage verify` re-hashes it.
//
// # What it concludes
//
// Every indicator is one of three verdicts. An attempt is an attack that left
// no sign of success — the thousands of scans and password guesses every
// public server receives. Suspicious is something a normal host also does,
// which a person should confirm. Compromise is something a healthy host does
// not do. Keeping attempts apart from the rest is most of the value: the
// question an operator actually has is not "was I attacked" (yes, constantly)
// but "did any of it work".
//
// Alongside the indicators it reports evidence gaps — questions the bundle
// cannot answer because the host never recorded what would answer them. Those
// come from the forensic-readiness domain, which is how the two halves of
// this work meet: readiness decides what triage will be able to see.
package triage

import (
	"time"
)

// Verdict is how much an indicator says about a compromise.
type Verdict string

const (
	Attempt    Verdict = "attempt"
	Suspicious Verdict = "suspicious"
	Compromise Verdict = "compromise"
)

// rank orders verdicts most serious first.
func (v Verdict) rank() int {
	switch v {
	case Compromise:
		return 0
	case Suspicious:
		return 1
	}
	return 2
}

// Evidence points at the bytes an indicator rests on.
type Evidence struct {
	Artifact string `json:"artifact"`
	Line     int    `json:"line,omitempty"`
	Text     string `json:"text"`
}

// Indicator is one conclusion with the evidence behind it.
type Indicator struct {
	ID       string     `json:"id"`
	Verdict  Verdict    `json:"verdict"`
	Title    string     `json:"title"`
	Detail   string     `json:"detail"`
	Count    int        `json:"count,omitempty"`
	First    time.Time  `json:"first,omitempty"`
	Last     time.Time  `json:"last,omitempty"`
	Evidence []Evidence `json:"evidence,omitempty"`
}

// Gap is a question the bundle cannot answer, and why.
type Gap struct {
	Question string `json:"question"`
	Reason   string `json:"reason"`
	Finding  string `json:"finding,omitempty"` // the readiness finding that closes it
}

// Event is one row of the timeline.
type Event struct {
	Time     time.Time `json:"time"`
	Source   string    `json:"source"`
	What     string    `json:"what"`
	Artifact string    `json:"artifact"`
}

// Artifact is one collected item as the manifest records it.
type Artifact struct {
	Name        string    `json:"name"` // logical name the analysis looks it up by
	Path        string    `json:"path"` // relative to the bundle
	Phase       int       `json:"phase"`
	Kind        string    `json:"kind"` // command, file, procfs, walk, derived
	Argv        []string  `json:"argv,omitempty"`
	Source      string    `json:"source,omitempty"`
	Error       string    `json:"error,omitempty"`
	SHA256      string    `json:"sha256"`
	Size        int64     `json:"size"`
	CollectedAt time.Time `json:"collected_at"`
}

// Manifest is the bundle's own record of how it was made.
type Manifest struct {
	Tool          string     `json:"tool"`
	Version       string     `json:"version"`
	BinarySHA256  string     `json:"binary_sha256,omitempty"`
	Host          string     `json:"host"`
	Kernel        string     `json:"kernel,omitempty"`
	Operator      string     `json:"operator,omitempty"`
	StartedUTC    time.Time  `json:"started_utc"`
	FinishedUTC   time.Time  `json:"finished_utc"`
	ClockSynced   string     `json:"clock_ntp_synchronized,omitempty"`
	Since         time.Time  `json:"since"`
	Artifacts     []Artifact `json:"artifacts"`
	Note          string     `json:"note"`
	AnalysisFiles []string   `json:"analysis_files"`
}

// Result is everything one analysis concluded.
type Result struct {
	Indicators []Indicator `json:"indicators"`
	Gaps       []Gap       `json:"gaps"`
	Timeline   []Event     `json:"-"`
}

// Counts returns how many indicators carry each verdict.
func (r Result) Counts() map[Verdict]int {
	out := map[Verdict]int{}
	for _, in := range r.Indicators {
		out[in.Verdict]++
	}
	return out
}
