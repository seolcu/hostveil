package model

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// enumCase describes one enum generically enough to run the same four
// assertions over all of them: names go out, names come back, the integers
// this package used to write still come back, and nonsense is refused.
type enumCase[T ~int] struct {
	kind   string
	values []T
	name   func(T) string
	parse  func(string) (T, bool)
	newPtr func() *T
	deref  func(*T) T
	// legacyOrdinal answers "what does the integer i in an old snapshot
	// mean now?". For every enum but Severity that is i itself. Severity's
	// scale went from four levels to three, so its old ordinals are remapped
	// and the identity assertion would be wrong — see legacySeverityOrdinals.
	legacyOrdinal func(int) (T, bool)
}

func run[T ~int](t *testing.T, c enumCase[T]) {
	t.Helper()
	t.Run(c.kind, func(t *testing.T) {
		if len(c.values) == 0 {
			t.Fatal("no values; the enum table is empty")
		}
		for _, v := range c.values {
			data, err := json.Marshal(v)
			if err != nil {
				t.Fatalf("marshal %v: %v", v, err)
			}

			// The whole point: a consumer of --json reads a word, not an
			// ordinal it has to keep its own table for.
			if got, want := string(data), `"`+c.name(v)+`"`; got != want {
				t.Errorf("marshal %v = %s, want %s", v, got, want)
			}

			p := c.newPtr()
			if err := json.Unmarshal(data, p); err != nil {
				t.Fatalf("unmarshal %s: %v", data, err)
			}
			if c.deref(p) != v {
				t.Errorf("%s round-tripped to %v", data, c.deref(p))
			}

			if got, ok := c.parse(c.name(v)); !ok || got != v {
				t.Errorf("parse(%q) = %v, %v", c.name(v), got, ok)
			}
		}

		// The integer form every snapshot written before names holds.
		// Dropping it would not fail loudly — it would make the previous scan
		// unreadable, which reads to a user as a host with no history rather
		// than as a format change.
		for n := 0; n < 8; n++ {
			want, valid := c.legacyOrdinal(n)
			p := c.newPtr()
			err := json.Unmarshal([]byte(fmt.Sprint(n)), p)
			if !valid {
				if err == nil {
					t.Errorf("legacy ordinal %d was accepted as a %s", n, c.kind)
				}
				continue
			}
			if err != nil {
				t.Fatalf("unmarshal legacy %d: %v", n, err)
			}
			if c.deref(p) != want {
				t.Errorf("legacy %d read back as %v, want %v", n, c.deref(p), want)
			}
		}

		// An unrecognised value is an error, not a zero. Resolving it
		// silently would turn a snapshot hostveil cannot read into one it
		// reads wrongly.
		for _, bad := range []string{`"nonsense"`, `9999`, `true`} {
			if err := json.Unmarshal([]byte(bad), c.newPtr()); err == nil {
				t.Errorf("unmarshal %s was accepted; an unknown %s must be an error", bad, c.kind)
			}
		}
	})
}

// identityOrdinal is the legacy answer for every enum whose numbering never
// moved: the integer means what it has always meant.
func identityOrdinal[T ~int](values []T) func(int) (T, bool) {
	return func(n int) (T, bool) {
		for _, v := range values {
			if int(v) == n {
				return v, true
			}
		}
		var zero T
		return zero, false
	}
}

func TestEnumsMarshalAsNamesAndReadBothForms(t *testing.T) {
	run(t, enumCase[Severity]{
		kind: "severity", values: AllSeverities(),
		name: Severity.String, parse: ParseSeverity,
		newPtr: func() *Severity { return new(Severity) },
		deref:  func(p *Severity) Severity { return *p },
		legacyOrdinal: func(n int) (Severity, bool) {
			s, ok := legacySeverityOrdinals[n]
			return s, ok
		},
	})
	run(t, enumCase[Source]{
		kind: "source", values: append(AllSources(), SourceUnset),
		name: Source.String, parse: ParseSource,
		newPtr:        func() *Source { return new(Source) },
		deref:         func(p *Source) Source { return *p },
		legacyOrdinal: identityOrdinal(append(AllSources(), SourceUnset)),
	})
	run(t, enumCase[RemediationKind]{
		kind: "remediation", values: AllRemediationKinds(),
		name: RemediationKind.String, parse: ParseRemediationKind,
		newPtr:        func() *RemediationKind { return new(RemediationKind) },
		deref:         func(p *RemediationKind) RemediationKind { return *p },
		legacyOrdinal: identityOrdinal(AllRemediationKinds()),
	})
	run(t, enumCase[ScanState]{
		kind: "scan state", values: AllScanStates(),
		name: ScanState.String, parse: ParseScanState,
		newPtr:        func() *ScanState { return new(ScanState) },
		deref:         func(p *ScanState) ScanState { return *p },
		legacyOrdinal: identityOrdinal(AllScanStates()),
	})
}

// legacySnapshot is a report as this package wrote them before the enums
// named themselves: every enum a bare integer.
//
// It is written out rather than generated, because a fixture built from the
// current tables would move with them and assert nothing. The numbers here
// are the numbers that are on operators' disks.
const legacySnapshot = `{
  "findings": [
    {"id": "ssh.rootlogin", "title": "SSH permits root login with a password",
     "severity": 1, "source": 2, "remediation": 2},
    {"id": "cve.outdated-image", "title": "Image ships known vulnerabilities",
     "severity": 0, "source": 5, "remediation": 4}
  ],
  "score": {"overall": 38, "applicable": true},
  "domains": [
    {"source": 2, "state": 2, "finding_count": 1},
    {"source": 5, "state": 4, "reason": "trivy could not read one image", "finding_count": 1},
    {"source": 10, "state": 3, "reason": "no sysctl"}
  ]
}`

// TestAPreviousScanStillReads is the compatibility claim the integer path
// exists for, made against a snapshot rather than against the tables.
//
// A scan snapshot is not a wire format that both ends redeploy together: it
// is a file on the host, and the next run reads what the last run wrote. If
// the integers stopped resolving, the delta would report every finding as
// new — "everything on this host changed" — with nothing anywhere saying why.
func TestAPreviousScanStillReads(t *testing.T) {
	var r Report
	if err := json.Unmarshal([]byte(legacySnapshot), &r); err != nil {
		t.Fatalf("a snapshot written by the previous release no longer reads: %v", err)
	}

	if len(r.Findings) != 2 {
		t.Fatalf("read %d findings, want 2", len(r.Findings))
	}
	for _, want := range []struct {
		id  string
		sev Severity
		src Source
		rem RemediationKind
	}{
		// severity 1 was High and severity 0 was Critical; both are High now.
		{"ssh.rootlogin", SeverityHigh, SourceSSH, RemediationReview},
		{"cve.outdated-image", SeverityHigh, SourceCVE, RemediationUnavailable},
	} {
		var got Finding
		for _, f := range r.Findings {
			if f.ID == want.id {
				got = f
			}
		}
		if got.Severity != want.sev || got.Source != want.src || got.Remediation != want.rem {
			t.Errorf("%s read back as %v/%v/%v, want %v/%v/%v",
				want.id, got.Severity, got.Source, got.Remediation, want.sev, want.src, want.rem)
		}
	}

	// Domain states carry the coverage claim, so misreading one turns
	// "could not look" into "looked and found nothing".
	states := map[Source]ScanState{}
	for _, d := range r.Domains {
		states[d.Source] = d.State
	}
	for src, want := range map[Source]ScanState{
		SourceSSH: ScanDone, SourceCVE: ScanDegraded, SourceSysctl: ScanSkipped,
	} {
		if states[src] != want {
			t.Errorf("%v read back as %v, want %v", src, states[src], want)
		}
	}

	// And what it writes back out is the new form, so a host converts on its
	// next scan rather than carrying integers forward forever.
	out, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"severity":"high"`, `"source":"ssh"`, `"remediation":"unavailable"`, `"state":"degraded"`} {
		if !strings.Contains(string(out), want) {
			t.Errorf("re-marshalled snapshot does not contain %s:\n%s", want, out)
		}
	}
}

// namedSnapshot is what the build *after* the integer one wrote: enums as
// names, with the severity levels under the interim names they carried
// between two changes on main — exposed / weak / hardening. No release ever
// shipped them, and anyone running from main has one of these on disk.
//
// It is a separate fixture from legacySnapshot rather than an edit to it,
// because the two say different things. The integer fixture proves the
// oldest form still resolves; this one proves that renaming the levels did
// not silently invalidate every snapshot written since. Written out for the
// same reason: a fixture built from the current tables would move with them.
const namedSnapshot = `{
  "findings": [
    {"id": "ssh.rootlogin", "title": "SSH permits root login with a password",
     "severity": "exposed", "source": "ssh", "remediation": "review"},
    {"id": "compose.ds006", "title": "Container can gain privileges",
     "severity": "weak", "source": "compose", "remediation": "auto"},
    {"id": "sysctl.rp-filter", "title": "Reverse path filtering is off",
     "severity": "hardening", "source": "sysctl", "remediation": "review"}
  ],
  "score": {"overall": 41, "applicable": true},
  "domains": [{"source": "ssh", "state": "done", "finding_count": 1}]
}`

// TestASnapshotFromTheInterimNamesStillReads covers the second rename.
//
// Renaming a level is invisible to the compiler and to every test that
// builds its input from the tables — those move together. What does not
// move is the file the last scan wrote. If "exposed" stopped resolving, the
// delta would report every finding on the host as new, which is the same
// failure the integer path exists to prevent, arriving one change later.
//
// No release carried these names, so no upgrade path needs them. What does
// is anyone tracking main, and the fixture costs four lines.
func TestASnapshotFromTheInterimNamesStillReads(t *testing.T) {
	var r Report
	if err := json.Unmarshal([]byte(namedSnapshot), &r); err != nil {
		t.Fatalf("a snapshot written under the previous level names no longer reads: %v", err)
	}
	if len(r.Findings) != 3 {
		t.Fatalf("read %d findings, want 3", len(r.Findings))
	}
	for _, want := range []struct {
		id  string
		sev Severity
	}{
		{"ssh.rootlogin", SeverityHigh},
		{"compose.ds006", SeverityMedium},
		{"sysctl.rp-filter", SeverityLow},
	} {
		var got Finding
		for _, f := range r.Findings {
			if f.ID == want.id {
				got = f
			}
		}
		if got.Severity != want.sev {
			t.Errorf("%s read back as %v, want %v", want.id, got.Severity, want.sev)
		}
	}

	// The ordering is the part that would fail silently. If two old names
	// collapsed onto one level the findings would still read, and only the
	// order they sort in would be wrong.
	if SeverityHigh >= SeverityMedium || SeverityMedium >= SeverityLow {
		t.Error("the levels no longer sort most-urgent-first")
	}
}

// TestEveryNameHostveilHasWrittenStillParses walks the names rather than a
// snapshot, so a level renamed a third time without an entry here fails
// immediately instead of at whatever a future operator's disk holds.
func TestEveryNameHostveilHasWrittenStillParses(t *testing.T) {
	for name, want := range map[string]Severity{
		// The current names.
		"high": SeverityHigh, "medium": SeverityMedium, "low": SeverityLow,
		// The urgency names, one release only.
		"exposed": SeverityHigh, "weak": SeverityMedium, "hardening": SeverityLow,
		// The four-level scale. critical and high merged, which is what
		// keeps scan's exit code meaning what it always did.
		"critical": SeverityHigh,
	} {
		got, ok := ParseSeverity(name)
		if !ok {
			t.Errorf("ParseSeverity(%q) failed, and hostveil has written that name to disk", name)
			continue
		}
		if got != want {
			t.Errorf("ParseSeverity(%q) = %v, want %v", name, got, want)
		}
	}
}
