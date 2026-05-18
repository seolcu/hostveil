package rules

import (
	"testing"

	"github.com/seolcu/hostveil/internal/compose"
)

func TestRuleEngineFindsExposureIssues(t *testing.T) {
	cf := &compose.ComposeFile{
		Services: map[string]compose.Service{
			"web": {
				Image: "nginx:latest",
				Ports: []compose.Port{
					{Published: 80, Target: 80, HostIP: "0.0.0.0"},
				},
			},
		},
	}

	engine := NewEngine()
	findings := engine.Scan(cf)

	if len(findings) == 0 {
		t.Fatal("expected findings, got none")
	}

	hasPublicBinding := false
	hasReverseProxy := false
	for _, f := range findings {
		if f.ID == "exposure.public_binding" {
			hasPublicBinding = true
		}
		if f.ID == "exposure.reverse_proxy_expected" {
			hasReverseProxy = true
		}
	}

	if !hasPublicBinding {
		t.Error("expected exposure.public_binding finding")
	}
	if !hasReverseProxy {
		t.Error("expected exposure.reverse_proxy_expected finding")
	}
}

func TestRuleEngineFindsPrivilegedContainer(t *testing.T) {
	cf := &compose.ComposeFile{
		Services: map[string]compose.Service{
			"app": {
				Image:      "myapp:latest",
				Privileged: true,
			},
		},
	}

	engine := NewEngine()
	findings := engine.Scan(cf)

	hasPrivileged := false
	for _, f := range findings {
		if f.ID == "permissions.privileged" {
			hasPrivileged = true
			if f.Severity.String() != "high" {
				t.Errorf("expected high severity, got %s", f.Severity)
			}
		}
	}

	if !hasPrivileged {
		t.Error("expected permissions.privileged finding")
	}
}

func TestRuleEngineFindsLatestTag(t *testing.T) {
	cf := &compose.ComposeFile{
		Services: map[string]compose.Service{
			"app": {
				Image: "myapp",
			},
		},
	}

	engine := NewEngine()
	findings := engine.Scan(cf)

	hasLatest := false
	for _, f := range findings {
		if f.ID == "updates.latest_tag" {
			hasLatest = true
		}
	}

	if !hasLatest {
		t.Error("expected updates.latest_tag finding")
	}
}

func TestRuleEngineFindsDefaultBridgeNetwork(t *testing.T) {
	cf := &compose.ComposeFile{
		Services: map[string]compose.Service{
			"app": {
				Image: "myapp:1.0",
			},
		},
		Networks: nil,
	}

	engine := NewEngine()
	findings := engine.Scan(cf)

	hasBridge := false
	for _, f := range findings {
		if f.ID == "network.default_bridge_used" {
			hasBridge = true
		}
	}

	if !hasBridge {
		t.Error("expected network.default_bridge_used finding")
	}
}
