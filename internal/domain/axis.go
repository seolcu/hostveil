package domain

import "strings"

type Axis int

const (
	AxisSensitiveData Axis = iota
	AxisExcessivePermissions
	AxisUnnecessaryExposure
	AxisUpdateSupplyChain
	AxisHostHardening
)

func (a Axis) String() string {
	switch a {
	case AxisSensitiveData:
		return "sensitive_data"
	case AxisExcessivePermissions:
		return "permissions"
	case AxisUnnecessaryExposure:
		return "exposure"
	case AxisUpdateSupplyChain:
		return "supply_chain"
	case AxisHostHardening:
		return "host_hardening"
	default:
		return "unknown"
	}
}

func ParseAxis(s string) (Axis, bool) {
	switch strings.ToLower(s) {
	case "sensitive_data":
		return AxisSensitiveData, true
	case "permissions", "excessive_permissions":
		return AxisExcessivePermissions, true
	case "exposure", "unnecessary_exposure":
		return AxisUnnecessaryExposure, true
	case "supply_chain", "update_supply_chain":
		return AxisUpdateSupplyChain, true
	case "host_hardening":
		return AxisHostHardening, true
	default:
		return 0, false
	}
}

func AllAxes() []Axis {
	return []Axis{
		AxisSensitiveData,
		AxisExcessivePermissions,
		AxisUnnecessaryExposure,
		AxisUpdateSupplyChain,
		AxisHostHardening,
	}
}

func (a Axis) Label() string {
	switch a {
	case AxisSensitiveData:
		return "Sensitive Data"
	case AxisExcessivePermissions:
		return "Excessive Permissions"
	case AxisUnnecessaryExposure:
		return "Unnecessary Exposure"
	case AxisUpdateSupplyChain:
		return "Update & Supply Chain"
	case AxisHostHardening:
		return "Host Hardening"
	default:
		return "Unknown"
	}
}
