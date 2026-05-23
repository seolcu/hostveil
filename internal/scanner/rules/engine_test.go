package rules

import (
	"testing"

	"github.com/seolcu/hostveil/internal/compose"
	"github.com/seolcu/hostveil/internal/domain"
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
		if f.ID == domain.FindingExposurePublicBinding {
			hasPublicBinding = true
		}
		if f.ID == domain.FindingExposureReverseProxy {
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
		if f.ID == domain.FindingPermissionsPrivileged {
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
		if f.ID == domain.FindingUpdatesLatestTag {
			hasLatest = true
		}
	}

	if !hasLatest {
		t.Error("expected updates.latest_tag finding")
	}
}

func TestServiceAwareFindsVaultwardenIssues(t *testing.T) {
	cf := &compose.ComposeFile{
		Services: map[string]compose.Service{
			"vaultwarden": {
				Image: "vaultwarden/server:latest",
				Ports: []compose.Port{{Published: 80, Target: 80, HostIP: "0.0.0.0"}},
				Environment: map[string]string{
					"DOMAIN":          "http://vault.example.com",
					"SIGNUPS_ALLOWED": "true",
					"ADMIN_TOKEN":     "lab-admin-token",
				},
			},
		},
	}

	engine := NewEngine()
	findings := engine.Scan(cf)

	ids := make(map[string]bool)
	for _, f := range findings {
		ids[f.ID] = true
	}

	if !ids[domain.FindingVaultwardenInsecureDomain] {
		t.Error("expected service.vaultwarden.insecure_domain")
	}
	if !ids[domain.FindingVaultwardenSignupsAllowed] {
		t.Error("expected service.vaultwarden.signups_allowed")
	}
	if !ids[domain.FindingVaultwardenAdminToken] {
		t.Error("expected service.vaultwarden.admin_token")
	}
}

func TestServiceAwareDetectsPostgresAndRedis(t *testing.T) {
	cf := &compose.ComposeFile{
		Services: map[string]compose.Service{
			"db": {
				Image: "postgres:16",
				Environment: map[string]string{
					"POSTGRES_PASSWORD": "postgres",
				},
			},
			"cache": {
				Image: "redis:7",
				Ports: []compose.Port{{Published: 6379, Target: 6379}},
			},
		},
	}

	engine := NewEngine()
	findings := engine.Scan(cf)

	ids := make(map[string]bool)
	for _, f := range findings {
		ids[f.ID] = true
	}

	if !ids[domain.FindingPostgresDefaultPassword] {
		t.Error("expected service.postgres.default_password")
	}
	if !ids[domain.FindingRedisNoPassword] {
		t.Error("expected service.redis.no_password")
	}
	if !ids[domain.FindingRedisPublicBind] {
		t.Error("expected service.redis.public_bind")
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
		if f.ID == domain.FindingNetworkDefaultBridge {
			hasBridge = true
		}
	}

	if !hasBridge {
		t.Error("expected network.default_bridge_used finding")
	}
}
