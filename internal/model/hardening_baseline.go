package model

// HardeningBaseline is a set of system-level security checks.
type HardeningBaseline struct {
	SysctlKeys            map[string]string `json:"sysctl_keys,omitempty"` // key -> expected value
	ExpectedPackages      []string          `json:"expected_packages,omitempty"`
	ExpectedServices      []string          `json:"expected_services,omitempty"`
}
