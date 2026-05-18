package scanner

import (
	"time"

	"github.com/seolcu/hostveil/internal/compose"
	"github.com/seolcu/hostveil/internal/discovery"
	"github.com/seolcu/hostveil/internal/domain"
	"github.com/seolcu/hostveil/internal/scanner/host"
	"github.com/seolcu/hostveil/internal/scanner/rules"
)

type Config struct {
	ComposePath string
	HostRoot    string
	UserMode    bool
}

func Run(cfg Config) (*domain.ScanResult, error) {
	start := time.Now()
	result := &domain.ScanResult{
		Metadata: domain.ScanMetadata{
			ScanMode:  domain.ScanModeExplicit,
			StartedAt: start,
		},
		ScoreReport: domain.ScoreReport{
			Overall:    100,
			AxisScores: make(map[domain.Axis]uint8),
			SeverityCounts: map[domain.Severity]int{
				domain.SeverityCritical: 0,
				domain.SeverityHigh:     0,
				domain.SeverityMedium:   0,
				domain.SeverityLow:      0,
			},
		},
	}

	// Parse compose file
	if cfg.ComposePath != "" {
		cf, err := compose.ParseFile(cfg.ComposePath)
		if err != nil {
			return nil, err
		}

		result.Metadata.ComposeFile = cfg.ComposePath

		// Run rule engine
		engine := rules.NewEngine()
		result.Findings = append(result.Findings, engine.Scan(cf)...)

		// Populate services
		for name, svc := range cf.Services {
			result.Metadata.Services = append(result.Metadata.Services, domain.ServiceSummary{
				Name:  name,
				Image: svc.Image,
			})
		}
	}

	// Run host checks
	if cfg.HostRoot != "" {
		result.Metadata.ScanMode = domain.ScanModeLive
		hostEngine := host.NewEngine(cfg.HostRoot)
		result.Findings = append(result.Findings, hostEngine.Scan()...)
	}

	// Docker discovery
	disc := discovery.Discover()
	switch disc.Status {
	case discovery.DockerAvailable:
		for _, p := range disc.Projects {
			result.Metadata.Warnings = append(result.Metadata.Warnings,
				"Discovered project: "+p.Name+" at "+p.ComposePath)
		}
	case discovery.DockerMissing:
		result.Metadata.Warnings = append(result.Metadata.Warnings,
			"Docker is not available. Compose-based scans only.")
	case discovery.DockerPermissionDenied:
		result.Metadata.Warnings = append(result.Metadata.Warnings,
			"Docker permission denied: "+disc.Err)
	}

	// Host runtime info
	hostInfo := discovery.GetHostRuntime(cfg.HostRoot)
	if len(hostInfo) > 0 {
		result.Metadata.HostRuntime = &domain.HostRuntimeInfo{
			Hostname:      hostInfo["hostname"],
			DockerVersion: hostInfo["docker_version"],
			Uptime:        hostInfo["uptime"],
			LoadAverage:   hostInfo["load_average"],
		}
	}

	// Calculate scores
	calculateScores(result)

	result.Metadata.Duration = time.Since(start)

	return result, nil
}

func calculateScores(result *domain.ScanResult) {
	if len(result.Findings) == 0 {
		return
	}

	// Count severities
	for _, f := range result.Findings {
		result.ScoreReport.SeverityCounts[f.Severity]++
	}

	// Count by axis
	axisCounts := make(map[domain.Axis]int)
	axisSeverity := make(map[domain.Axis]int)
	for _, f := range result.Findings {
		axisCounts[f.Axis]++
		sev := int(f.Severity)
		axisSeverity[f.Axis] += sev
	}

	// Calculate per-axis scores (100 - deductions)
	for _, axis := range domain.AllAxes() {
		count := axisCounts[axis]
		totalSev := axisSeverity[axis]
		deduction := uint8(totalSev) * uint8(count) * 5
		score := uint8(100)
		if deduction < 100 {
			score = 100 - deduction
		} else {
			score = 0
		}
		result.ScoreReport.AxisScores[axis] = score
	}

	// Overall score (average of axis scores)
	total := uint8(0)
	for _, axis := range domain.AllAxes() {
		total += result.ScoreReport.AxisScores[axis]
	}
	if len(domain.AllAxes()) > 0 {
		result.ScoreReport.Overall = total / uint8(len(domain.AllAxes()))
	}
}
