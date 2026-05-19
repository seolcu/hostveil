package scanner

import (
	"os"
	"path/filepath"
	"time"

	"github.com/seolcu/hostveil/internal/adapter"
	"github.com/seolcu/hostveil/internal/compose"
	"github.com/seolcu/hostveil/internal/discovery"
	"github.com/seolcu/hostveil/internal/domain"
	"github.com/seolcu/hostveil/internal/scanner/host"
	"github.com/seolcu/hostveil/internal/scanner/rules"
)

type Config struct {
	UserMode     bool
	ComposeFiles []string // optional explicit paths (for testing/programmatic use)
}

func Run(cfg Config) (*domain.ScanResult, error) {
	start := time.Now()
	result := &domain.ScanResult{
		Metadata: domain.ScanMetadata{
			ScanMode:  scanMode(cfg.UserMode),
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

	// 1. Collect compose files: explicit paths or auto-discover
	var projects []discovery.Project
	if len(cfg.ComposeFiles) > 0 {
		for _, path := range cfg.ComposeFiles {
			abs, err := filepath.Abs(path)
			if err != nil {
				continue
			}
			projects = append(projects, discovery.Project{
				Name:        filepath.Base(filepath.Dir(abs)),
				ComposePath: abs,
			})
		}
	} else {
		disc := discovery.Discover(cfg.UserMode)
		projects = disc.Projects
		switch disc.Status {
		case discovery.DockerMissing:
			result.Metadata.Warnings = append(result.Metadata.Warnings,
				"Docker is not available. Compose-based scans only.")
		case discovery.DockerPermissionDenied:
			result.Metadata.Warnings = append(result.Metadata.Warnings,
				"Docker permission denied. Run with sudo or install Docker.")
		}
	}

	// 2. Parse and scan each compose file
	serviceSeen := make(map[string]bool)
	ruleEngine := rules.NewEngine()

	for _, p := range projects {
		cf, err := compose.ParseFile(p.ComposePath)
		if err != nil {
			result.Metadata.Warnings = append(result.Metadata.Warnings,
				"Failed to parse "+filepath.Base(p.ComposePath)+": "+err.Error())
			continue
		}

		result.Metadata.ComposeFile = p.ComposePath
		result.Metadata.InfoMessages = append(result.Metadata.InfoMessages,
			"Discovered project: "+p.Name+" at "+p.ComposePath)

		// Run rule engine on this compose file
		findings := ruleEngine.Scan(cf)
		result.Findings = append(result.Findings, findings...)

		// Collect services (deduplicated)
		for name, svc := range cf.Services {
			if serviceSeen[name] {
				continue
			}
			serviceSeen[name] = true
			result.Metadata.Services = append(result.Metadata.Services, domain.ServiceSummary{
				Name:  name,
				Image: svc.Image,
			})
		}
	}

	// 3. Run host checks (unless user-mode)
	if !cfg.UserMode {
		hostRoot := "/"
		if _, err := os.Stat(hostRoot); err == nil {
			hostEngine := host.NewEngine(hostRoot)
			hostFindings := hostEngine.Scan()
			result.Findings = append(result.Findings, hostFindings...)
		}
	}

	// 4. Auto-detect and run available adapters
	adapters := adapter.DetectAvailable()
	for _, a := range adapters {
		result.Metadata.Adapters = append(result.Metadata.Adapters, domain.AdapterInfo{
			Name:   a.Name(),
			Status: domain.AdapterAvailable,
			Detail: "detected via PATH",
		})
		result.Metadata.InfoMessages = append(result.Metadata.InfoMessages,
			"Adapter detected: "+a.Name())
	}
	if len(adapters) > 0 {

		// Run each adapter against the first project
		if len(projects) > 0 {
			target := projects[0].ComposePath
			adapterFindings := adapter.RunAll(adapters, target)
			result.Findings = append(result.Findings, adapterFindings...)
		}
	}

	// 5. Host runtime info
	hostInfo := discovery.GetHostRuntime("")
	if len(hostInfo) > 0 {
		result.Metadata.HostRuntime = &domain.HostRuntimeInfo{
			Hostname:      hostInfo["hostname"],
			DockerVersion: hostInfo["docker_version"],
			Uptime:        hostInfo["uptime"],
			LoadAverage:   hostInfo["load_average"],
		}
	}

	// 6. Calculate scores
	calculateScores(result)

	result.Metadata.Duration = time.Since(start)

	return result, nil
}

func scanMode(userMode bool) domain.ScanMode {
	if userMode {
		return domain.ScanModeExplicit
	}
	return domain.ScanModeLive
}

func calculateScores(result *domain.ScanResult) {
	if len(result.Findings) == 0 {
		return
	}

	for _, f := range result.Findings {
		result.ScoreReport.SeverityCounts[f.Severity]++
	}

	axisCounts := make(map[domain.Axis]int)
	axisSeverity := make(map[domain.Axis]int)
	for _, f := range result.Findings {
		axisCounts[f.Axis]++
		sev := int(f.Severity)
		axisSeverity[f.Axis] += sev
	}

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

	total := uint8(0)
	for _, axis := range domain.AllAxes() {
		total += result.ScoreReport.AxisScores[axis]
	}
	if len(domain.AllAxes()) > 0 {
		result.ScoreReport.Overall = total / uint8(len(domain.AllAxes()))
	}
}
