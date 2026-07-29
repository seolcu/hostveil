package check

import "strings"

// Coverage is a checker's running ledger of what it did and did not manage to
// examine. Record each success with Covered and each blind spot with Missed;
// Err then returns nil or the *PartialError describing every gap at once.
//
// It exists because the alternative — deciding, at the point a gap is
// discovered, whether to return now — loses gaps. Both container checkers did
// exactly that: the CVE domain reported an unparsed compose file only when no
// image had also failed to scan, and the compose domain reported it only when
// container enumeration had also succeeded. Hit both at once, as a host with
// one broken stack and one unreachable registry does, and one of the two
// vanished from the reason string while its images went unexamined. The
// counters lied in the same direction — the very thing the surviving branch's
// own comment says a checker must never do.
//
// A ledger cannot make that mistake: nothing is returned until everything has
// been recorded, so a second gap can only add to the first.
type Coverage struct {
	covered int
	total   int
	reasons []string
}

// Covered records n units the checker successfully examined.
func (c *Coverage) Covered(n int) {
	c.covered += n
	c.total += n
}

// Missed records n units the checker could not examine, and the
// plain-language reason shown in every UI.
//
// n may be zero for a gap with no unit of its own: "cannot enumerate the
// containers started outside Compose" is unmeasurable by definition, since
// the units it would have added are precisely the ones that could not be
// counted. Such a gap still degrades the domain — it contributes a reason
// without pretending to a denominator it does not know.
//
// An empty reason is the mirror case: units known to be uncovered whose cause
// another entry has already stated. The dockerd domain cannot resolve the
// docker group when it could not resolve the socket, and repeating the socket
// reason under a second heading tells the operator nothing. The units still
// lower the fraction; only the sentence is suppressed.
func (c *Coverage) Missed(n int, reason string) {
	c.total += n
	if reason != "" {
		c.reasons = append(c.reasons, reason)
	}
}

// Err returns nil when nothing was missed, and otherwise a *PartialError
// joining every recorded reason. Reasons are joined with "; " and appear in
// the order they were recorded, so a checker controls its own emphasis by
// recording the more fundamental gap first.
//
// It keys on the reasons, not the counters: a gap whose reason was suppressed
// as a duplicate is one another entry already reports, so it cannot be the
// only thing standing between a domain and a clean result.
func (c *Coverage) Err() error {
	if len(c.reasons) == 0 {
		return nil
	}
	return &PartialError{
		Reason:  strings.Join(c.reasons, "; "),
		Covered: c.covered,
		Total:   c.total,
	}
}
