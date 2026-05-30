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
	ToolDegraded
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
	ScoreBreakdown  ScoreBreakdown
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
	sp.updateScoreLocked()
}

func (sp *ScanProgress) Recalculate() {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	sp.updateScoreLocked()
}

func (sp *ScanProgress) updateScoreLocked() {
	breakdown := ScoreFindings(sp.Findings)
	sp.Score = breakdown.Overall
	sp.Grade = breakdown.Grade
	sp.ScoreBreakdown = breakdown
}

func (sp *ScanProgress) ResetForRescan() {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	sp.Phase = "loading"
	sp.Score = 0
	sp.Grade = ""
	sp.ScoreBreakdown = ScoreBreakdown{}
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
	if count > 0 {
		sp.updateScoreLocked()
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
	if len(alsoFixed) > 0 {
		sp.updateScoreLocked()
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
	ScoreBreakdown  ScoreBreakdown           `json:"score_breakdown"`
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
	breakdown := sp.ScoreBreakdown
	if len(breakdown.Axes) > 0 {
		breakdown.Axes = append([]ScoreAxis(nil), breakdown.Axes...)
	}
	return Snapshot{
		Phase:           sp.Phase,
		UpdateAvailable: sp.UpdateAvailable,
		Tools:           tools,
		Findings:        findings,
		Score:           sp.Score,
		Grade:           sp.Grade,
		ScoreBreakdown:  breakdown,
		Hostname:        sp.Hostname,
		LocalIP:         sp.LocalIP,
	}
}
