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
}

func (sp *ScanProgress) SetUpdateAvailable(v string) {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	sp.UpdateAvailable = v
}

func (sp *ScanProgress) SetGrade(g string) {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	sp.Grade = g
}

type ToolStateJSON struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
}

type Snapshot struct {
	Phase           string                  `json:"phase"`
	UpdateAvailable string                  `json:"update_available"`
	Tools           map[string]ToolStateJSON `json:"tools"`
	Findings        []Finding               `json:"findings"`
	Score           uint8                   `json:"score"`
	Grade           string                  `json:"grade"`
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
	}
}

func (sp *ScanProgress) ToolCounts() (total, fixable int, sources map[Source]int) {
	sp.mu.RLock()
	defer sp.mu.RUnlock()
	sources = map[Source]int{}
	for _, f := range sp.Findings {
		if f.IsFixable() {
			fixable++
		}
		sources[f.Source]++
	}
	return len(sp.Findings), fixable, sources
}

type ProgressTick struct{}

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

func CountFixable(findings []Finding) int {
	n := 0
	for _, f := range findings {
		if f.IsFixable() {
			n++
		}
	}
	return n
}
