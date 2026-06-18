package model

import "time"

// AIMethod is the locked enum for AIRequest.method.
type AIMethod string

const (
	AIMethodExplain   AIMethod = "explain"
	AIMethodRisk      AIMethod = "risk"
	AIMethodRecommend AIMethod = "recommend"
)

// AIFailureClass is the locked enum for AIRequest.failure_class.
type AIFailureClass string

const (
	AIFailureUnreachable            AIFailureClass = "unreachable"
	AIFailureTimeout                AIFailureClass = "timeout"
	AIFailureRateLimit              AIFailureClass = "rate-limit"
	AIFailureMalformed              AIFailureClass = "malformed"
	AIFailurePromptInjection        AIFailureClass = "prompt-injection-suspected"
	AIFailureConsentDenied          AIFailureClass = "consent-denied"
	AIFailureAuthFailed             AIFailureClass = "auth-failed"
	AIFailureOther                  AIFailureClass = "other"
)

// AIRequest is a single AI call.
type AIRequest struct {
	ID                    string         `json:"id"`
	AIProviderID          string         `json:"ai_provider_id"`
	HostID                string         `json:"host_id"`
	RequestedAt           time.Time      `json:"requested_at"`
	Method                AIMethod       `json:"method"`
	Model                 string         `json:"model"`
	RedactedPromptSHA256  string         `json:"redacted_prompt_sha256"`
	ResponseText          string         `json:"response_text,omitempty"`
	FailureClass          AIFailureClass `json:"failure_class,omitempty"`
	TokensIn              *int           `json:"tokens_in,omitempty"`
	TokensOut             *int           `json:"tokens_out,omitempty"`
	LatencyMS             int            `json:"latency_ms"`
	LatencyBudgetMS       int            `json:"latency_budget_ms"`
	TUISessionID          string         `json:"tui_session_id,omitempty"`
	WebSessionID          string         `json:"web_session_id,omitempty"`
}
