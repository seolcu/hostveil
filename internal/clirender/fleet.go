package clirender

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/seolcu/hostveil/internal/model"
)

// Fleet renders a fleet scan as one row per host, worst first.
//
// A host that could not be scanned is a row with its reason and no number —
// never a 0, which would read as the worst host rather than as one nobody
// looked at. A host whose scan was incomplete says how many domains did not
// fully run, for the same reason the single-host report does.
func Fleet(f model.Fleet, opts Options) string {
	c := palette(opts.Color)
	entries := f.WorstFirst()

	hostW := len("HOST")
	for _, e := range entries {
		if n := utf8.RuneCountInString(e.Host); n > hostW {
			hostW = n
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s%-*s  %5s  %5s  %4s  %4s  %4s  %s%s\n", c.bold, hostW, "HOST", "SCORE", "AFTER", "HIGH", "MED", "LOW", "NOTE", c.reset)
	for _, e := range entries {
		pad := strings.Repeat(" ", hostW-utf8.RuneCountInString(e.Host))
		if e.Report == nil {
			fmt.Fprintf(&b, "%s%s  %s%5s  %5s  %4s  %4s  %4s  %s%s\n", e.Host, pad, c.dim, "—", "—", "—", "—", "—", c.reset, c.red+e.Error+c.reset)
			continue
		}
		r := e.Report
		high, med, low := countActive(r.Findings)
		score, after := "N/A", "—"
		scoreCol := c.dim
		if r.Score.Applicable {
			score = fmt.Sprintf("%d", r.Score.Overall)
			scoreCol = scoreColor(c, r.Score.Overall)
			if v, show := r.Score.Headroom(); show {
				after = fmt.Sprintf("%d", v)
			}
		}
		note := ""
		if n := r.IncompleteDomains(); n > 0 {
			note = c.dim + fmt.Sprintf("%d domain(s) did not fully run", n) + c.reset
		}
		highCol := ""
		if high > 0 {
			highCol = c.red
		}
		fmt.Fprintf(&b, "%s%s  %s%5s%s  %5s  %s%4d%s  %4d  %4d  %s\n", e.Host, pad, scoreCol, score, c.reset, after, highCol, high, c.reset, med, low, note)
	}

	scanned, failed := 0, 0
	for _, e := range entries {
		if e.Report == nil {
			failed++
		} else {
			scanned++
		}
	}
	fmt.Fprintf(&b, "\n%d host(s) scanned", scanned)
	if failed > 0 {
		fmt.Fprintf(&b, ", %s%d could not be%s", c.red, failed, c.reset)
	}
	b.WriteString(". Fixes are applied on each host itself: `ssh <host> hostveil`.\n")
	return b.String()
}

// FleetJSON renders a fleet scan as indented JSON, in the order the hosts
// were named.
func FleetJSON(f model.Fleet) (string, error) {
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// countActive counts the findings still standing, by severity.
func countActive(fs []model.Finding) (high, med, low int) {
	for _, f := range fs {
		if !f.Active() {
			continue
		}
		switch f.Severity {
		case model.SeverityHigh:
			high++
		case model.SeverityMedium:
			med++
		case model.SeverityLow:
			low++
		}
	}
	return high, med, low
}
