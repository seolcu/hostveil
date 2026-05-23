package host

import "github.com/seolcu/hostveil/internal/domain"

type FIMCheck struct{ Root string }

func (c *FIMCheck) Name() string { return "fim" }

func (c *FIMCheck) Scan(_ string) []domain.Finding {
	return []domain.Finding{
		hostFinding(
			domain.FindingHostFIMNoTool,
			domain.AxisHostHardening,
			domain.SeverityMedium,
			"fim",
			"File integrity monitoring (FIM) not detected",
			"Check whether AIDE, Tripwire, Samhain, or similar FIM tools are installed.",
			"FIM detects unauthorized file changes that may indicate a compromise.",
			"Install and configure AIDE: sudo apt install aide && sudo aideinit",
		),
	}
}
