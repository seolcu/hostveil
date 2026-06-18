package model

import "testing"

func TestSeverityValid(t *testing.T) {
	for _, s := range []Severity{SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical} {
		if !s.Valid() {
			t.Errorf("Severity(%q).Valid() = false, want true", s)
		}
	}
	if Severity("nope").Valid() {
		t.Errorf("Severity(\"nope\").Valid() = true, want false")
	}
}

func TestCategoryValid(t *testing.T) {
	for _, c := range []Category{
		CategorySSH, CategoryDocker, CategoryImageCVE, CategoryReverseProxy,
		CategorySSLTLS,
		CategoryHardeningFirewall, CategoryHardeningFail2ban,
		CategoryHardeningUnattended, CategoryHardeningSysctl,
		CategoryHardeningUpdates,
	} {
		if !c.Valid() {
			t.Errorf("Category(%q).Valid() = false, want true", c)
		}
	}
	if Category("nope").Valid() {
		t.Errorf("Category(\"nope\").Valid() = true, want false")
	}
}

func TestServiceStatusValid(t *testing.T) {
	for _, s := range []ServiceStatus{ServiceRunning, ServiceStopped, ServiceNotInstalled} {
		if !s.Valid() {
			t.Errorf("ServiceStatus(%q).Valid() = false, want true", s)
		}
	}
	if ServiceStatus("maybe").Valid() {
		t.Errorf("ServiceStatus(\"maybe\").Valid() = true, want false")
	}
}

func TestStateAndKindEnums(t *testing.T) {
	for _, s := range []State{StateNew, StateStillPresent, StateResolved, StateSuppressed} {
		if s == "" {
			t.Errorf("empty State")
		}
	}
	for _, k := range []EntityRefKind{
		EntityRefKindHost, EntityRefKindService, EntityRefKindConfigFile,
		EntityRefKindSetting, EntityRefKindContainerImage, EntityRefKindVulnerability,
	} {
		if k == "" {
			t.Errorf("empty EntityRefKind")
		}
	}
	for _, k := range []AIProviderKind{AIProviderOllama, AIProviderAnthropic, AIProviderCustom} {
		if k == "" {
			t.Errorf("empty AIProviderKind")
		}
	}
	for _, t2 := range []AIPrivacyTier{AITierLocal, AITierCloudSelfHosted, AITierCloudVendor} {
		if t2 == "" {
			t.Errorf("empty AIPrivacyTier")
		}
	}
	for _, m := range []AIMethod{AIMethodExplain, AIMethodRisk, AIMethodRecommend} {
		if m == "" {
			t.Errorf("empty AIMethod")
		}
	}
	for _, f := range []AIFailureClass{
		AIFailureUnreachable, AIFailureTimeout, AIFailureRateLimit, AIFailureMalformed,
		AIFailurePromptInjection, AIFailureConsentDenied, AIFailureAuthFailed, AIFailureOther,
	} {
		if f == "" {
			t.Errorf("empty AIFailureClass")
		}
	}
}
