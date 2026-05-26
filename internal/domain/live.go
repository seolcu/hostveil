// Package domain defines core types: Finding, Severity, Source, and scan progress.
package domain

import "sync"

type ToolStatus int

const (
	ToolPending ToolStatus = iota
	ToolRunning
	ToolDone
	ToolSkipped
	ToolError
)

type ToolState struct {
	Status  ToolStatus
	Message string
}

type ScanProgress struct {
	mu              sync.RWMutex
	Phase           string // "loading" | "complete"
	UpdateAvailable string
	Tools           map[string]*ToolState
	Findings        []Finding
	Score           uint8
	Grade           string
	Hostname        string
	LocalIP         string
}

func NewScanProgress(noUpdateCheck bool) *ScanProgress {
	sp := &ScanProgress{
		Phase: "loading",
		Tools: map[string]*ToolState{
			"trivy": {Status: ToolPending, Message: "Waiting..."},
			"lynis": {Status: ToolPending, Message: "Waiting..."},
		},
	}
	if !noUpdateCheck {
		sp.Tools["update"] = &ToolState{Status: ToolPending, Message: "Checking for updates..."}
	}
	return sp
}

func (sp *ScanProgress) SetToolStatus(tool string, status ToolStatus, message string) {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	sp.Tools[tool] = &ToolState{Status: status, Message: message}
}

func (sp *ScanProgress) ToolState(tool string) ToolState {
	sp.mu.RLock()
	defer sp.mu.RUnlock()
	if s, ok := sp.Tools[tool]; ok {
		return *s
	}
	return ToolState{}
}

func (sp *ScanProgress) AllToolsDone() bool {
	sp.mu.RLock()
	defer sp.mu.RUnlock()
	for _, s := range sp.Tools {
		if s.Status == ToolPending || s.Status == ToolRunning {
			return false
		}
	}
	return true
}

func (sp *ScanProgress) AddFindings(findings []Finding) {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	sp.Findings = append(sp.Findings, findings...)
}

func (sp *ScanProgress) Finalize() {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	sp.Phase = "complete"
	sp.Score = CalculateScore(sp.Findings)
	sp.Grade = GradeFromScore(sp.Score)
}

func (sp *ScanProgress) Recalculate() {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	sp.Score = CalculateScore(sp.Findings)
	sp.Grade = GradeFromScore(sp.Score)
}

func (sp *ScanProgress) ResetForRescan() {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	sp.Phase = "loading"
	sp.Score = 0
	sp.Grade = ""
	sp.Findings = nil
	for name, t := range sp.Tools {
		if name == "update" {
			continue
		}
		t.Status = ToolPending
		t.Message = "Waiting..."
	}
}

func (sp *ScanProgress) SetUpdateAvailable(v string) {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	sp.UpdateAvailable = v
}

// MarkFixed sets Fixed=true for the finding with the given ID.
// Returns the number of findings marked (0 if not found).
func (sp *ScanProgress) MarkFixed(id string) int {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	count := 0
	for i := range sp.Findings {
		if sp.Findings[i].ID == id && !sp.Findings[i].Fixed {
			sp.Findings[i].Fixed = true
			count++
		}
	}
	return count
}

// MarkRelatedFixed marks findings as Fixed when they:
// 1. Match the same fix (via matchFn)
// 2. Share the same Service (image/compose service)
// 3. Are not already fixed
// Returns IDs of newly marked findings.
func (sp *ScanProgress) MarkRelatedFixed(excludeID string, service string, matchFn func(id string) bool) []string {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	var alsoFixed []string
	for i := range sp.Findings {
		f := &sp.Findings[i]
		if f.ID == excludeID {
			continue
		}
		if f.Fixed {
			continue
		}
		if f.Service == "" || f.Service != service {
			continue
		}
		if !matchFn(f.ID) {
			continue
		}
		f.Fixed = true
		alsoFixed = append(alsoFixed, f.ID)
	}
	return alsoFixed
}

type ToolStateJSON struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
}

type Snapshot struct {
	Phase           string                   `json:"phase"`
	UpdateAvailable string                   `json:"update_available"`
	Tools           map[string]ToolStateJSON `json:"tools"`
	Findings        []Finding                `json:"findings"`
	Score           uint8                    `json:"score"`
	Grade           string                   `json:"grade"`
	Hostname        string                   `json:"hostname"`
	LocalIP         string                   `json:"local_ip"`
}

func (sp *ScanProgress) Snapshot() Snapshot {
	sp.mu.RLock()
	defer sp.mu.RUnlock()
	tools := make(map[string]ToolStateJSON, len(sp.Tools))
	for k, v := range sp.Tools {
		tools[k] = ToolStateJSON{Status: int(v.Status), Message: v.Message}
	}
	findings := make([]Finding, len(sp.Findings))
	copy(findings, sp.Findings)
	return Snapshot{
		Phase:           sp.Phase,
		UpdateAvailable: sp.UpdateAvailable,
		Tools:           tools,
		Findings:        findings,
		Score:           sp.Score,
		Grade:           sp.Grade,
		Hostname:        sp.Hostname,
		LocalIP:         sp.LocalIP,
	}
}

func CalculateScore(findings []Finding) uint8 {
	if len(findings) == 0 {
		return 100
	}
	total := 0
	for _, f := range findings {
		switch f.Severity {
		case SeverityCritical:
			total += 4
		case SeverityHigh:
			total += 3
		case SeverityMedium:
			total += 2
		case SeverityLow:
			total += 1
		}
	}
	score := 100 - total*5
	if score < 0 {
		return 0
	}
	return uint8(score)
}

func GradeFromScore(score uint8) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 70:
		return "B"
	case score >= 50:
		return "C"
	case score >= 30:
		return "D"
	default:
		return "F"
	}
}
