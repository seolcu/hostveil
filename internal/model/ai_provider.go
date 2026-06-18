package model

import "time"

// AIProviderKind is the locked enum for AIProvider.kind.
type AIProviderKind string

const (
	AIProviderOllama    AIProviderKind = "ollama"
	AIProviderAnthropic AIProviderKind = "anthropic"
	AIProviderCustom    AIProviderKind = "custom"
)

// AIPrivacyTier is the locked enum for AIProvider.privacy_tier.
type AIPrivacyTier string

const (
	AITierLocal          AIPrivacyTier = "local"
	AITierCloudSelfHosted AIPrivacyTier = "cloud-self-hosted"
	AITierCloudVendor    AIPrivacyTier = "cloud-vendor"
)

// AIProvider is the configuration of a single AI provider.
type AIProvider struct {
	ID                 string         `json:"id"`
	Name               string         `json:"name"`
	HostID             string         `json:"host_id"`
	Kind               AIProviderKind `json:"kind"`
	BaseURL            string         `json:"base_url"`
	Model              string         `json:"model"`
	APIKeyRef          string         `json:"api_key_ref,omitempty"`
	PrivacyTier        AIPrivacyTier  `json:"privacy_tier"`
	ConsentRequired    bool           `json:"consent_required"`
	ConsentRecordedAt  *time.Time     `json:"consent_recorded_at,omitempty"`
	Enabled            bool           `json:"enabled"`
}
