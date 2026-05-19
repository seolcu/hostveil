package adapter

import "github.com/seolcu/hostveil/internal/domain"

// DetectAvailable returns all adapters whose underlying tool is found in PATH.
func DetectAvailable() []Adapter {
	all := All()
	var available []Adapter
	for _, a := range all {
		if a.IsAvailable() {
			available = append(available, a)
		}
	}
	return available
}

// RunAll executes all given adapters and merges their findings.
func RunAll(adapters []Adapter, target string) []domain.Finding {
	var findings []domain.Finding
	for _, a := range adapters {
		f, err := a.Run(target)
		if err != nil {
			continue
		}
		findings = append(findings, f...)
	}
	return findings
}
