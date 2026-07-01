package tui

import (
	"sort"
	"strings"

	"github.com/seolcu/hostveil/internal/domain"
)

type filterState struct {
	query       string
	severity    string
	source      string
	remediation string
	sortBy      string
	sortDir     string // "asc" | "desc"
	service     string
}

// visibleFindings returns the filtered+sorted findings for the current
// model. The result is memoized per-render-frame via visibleCache so that
// callers within a single View() call don't re-filter+sort repeatedly.
// Callers that mutate m.filter/m.snap/selectedSet must call invalidateVisibleCache().
func (m *model) visibleFindings() []domain.Finding {
	if m.visibleCache != nil {
		return m.visibleCache
	}
	items := m.snap.Findings
	f := m.filter
	filtered := make([]domain.Finding, 0, len(items))
	for _, item := range items {
		if f.severity != "all" && item.Severity.String() != f.severity {
			continue
		}
		if f.source != "all" && item.Source.String() != f.source {
			continue
		}
		if f.remediation != "all" && item.Remediation.String() != f.remediation {
			continue
		}
		if f.service != "all" && item.Service != f.service {
			continue
		}
		if f.query != "" && !findingMatches(item, f.query) {
			continue
		}
		filtered = append(filtered, item)
	}
	sortFindings(filtered, f.sortBy, f.sortDir)
	m.visibleCache = filtered
	return filtered
}

func (m *model) invalidateVisibleCache() { m.visibleCache = nil }

func findingMatches(f domain.Finding, q string) bool {
	q = strings.ToLower(q)
	for _, s := range []string{f.ID, f.Title, f.Description, f.HowToFix, f.Service, f.Severity.String(), f.Source.String(), f.Remediation.String()} {
		if strings.Contains(strings.ToLower(s), q) {
			return true
		}
	}
	return false
}

func sortFindings(findings []domain.Finding, sortBy, sortDir string) {
	dir := 1
	if sortDir == "desc" {
		dir = -1
	}
	sevOrder := func(s domain.Severity) int {
		switch s {
		case domain.SeverityCritical:
			return 0
		case domain.SeverityHigh:
			return 1
		case domain.SeverityMedium:
			return 2
		default:
			return 3
		}
	}
	less := func(a, b int) bool {
		if dir == -1 {
			return b < a
		}
		return a < b
	}
	switch sortBy {
	case "severity":
		sort.Slice(findings, func(i, j int) bool {
			si, sj := sevOrder(findings[i].Severity), sevOrder(findings[j].Severity)
			if si != sj {
				return less(si, sj)
			}
			return less(strings.Compare(findings[i].Title, findings[j].Title), 0)
		})
	case "source":
		sort.Slice(findings, func(i, j int) bool {
			if findings[i].Source != findings[j].Source {
				ci := strings.Compare(findings[i].Source.String(), findings[j].Source.String())
				return less(ci, 0)
			}
			return less(sevOrder(findings[i].Severity), sevOrder(findings[j].Severity))
		})
	case "title":
		sort.Slice(findings, func(i, j int) bool {
			ci := strings.Compare(findings[i].Title, findings[j].Title)
			return less(ci, 0)
		})
	case "remediation":
		sort.Slice(findings, func(i, j int) bool {
			if findings[i].Remediation != findings[j].Remediation {
				ci := strings.Compare(findings[i].Remediation.String(), findings[j].Remediation.String())
				return less(ci, 0)
			}
			return less(sevOrder(findings[i].Severity), sevOrder(findings[j].Severity))
		})
	}
}

func (m *model) cycleSourceFilter() {
	switch m.filter.source {
	case "all":
		m.filter.source = "trivy"
	case "trivy":
		m.filter.source = "lynis"
	case "lynis":
		m.filter.source = "compose"
	default:
		m.filter.source = "all"
	}
}

func (m *model) cycleRemediationFilter() {
	switch m.filter.remediation {
	case "all":
		m.filter.remediation = "auto"
	case "auto":
		m.filter.remediation = "review"
	case "review":
		m.filter.remediation = "unavailable"
	case "unavailable":
		m.filter.remediation = "manual"
	default:
		m.filter.remediation = "all"
	}
}

func (m *model) cycleServiceFilter() {
	services := []string{"all"}
	seen := map[string]bool{"all": true}
	for _, f := range m.snap.Findings {
		if f.Service != "" && !seen[f.Service] {
			seen[f.Service] = true
			services = append(services, f.Service)
		}
	}
	if len(services) <= 1 {
		return
	}
	idx := -1
	for i, s := range services {
		if s == m.filter.service {
			idx = i
			break
		}
	}
	next := (idx + 1) % len(services)
	m.filter.service = services[next]
}

func (m *model) cycleSortOrder() {
	switch m.filter.sortBy {
	case "severity":
		m.filter.sortBy = "source"
	case "source":
		m.filter.sortBy = "title"
	case "title":
		m.filter.sortBy = "remediation"
	default:
		m.filter.sortBy = "severity"
	}
}
