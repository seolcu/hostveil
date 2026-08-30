package ai

import (
	"context"
	"fmt"

	"github.com/seolcu/hostveil/internal/model"
)

// FromEnv builds the Explainer selected by HOSTVEIL_AI_PROVIDER: "ollama"
// (the default — local, so nothing leaves the host), "anthropic" (the
// Claude API), or "openai" (any vendor speaking the OpenAI chat-completions
// shape). An operator must name an off-host provider explicitly; enabling
// --ai never sends anything off the host on its own.
func FromEnv() Explainer {
	switch p := envOr("HOSTVEIL_AI_PROVIDER", "ollama"); p {
	case "ollama":
		return NewOllama()
	case "anthropic":
		return NewAnthropic()
	case "openai":
		return NewOpenAICompat()
	default:
		return unknownProvider{name: p}
	}
}

// unknownProvider reports itself Available so the engine actually calls
// Explain and surfaces which value was wrong, rather than the generic
// "no AI provider is reachable" message every other misconfiguration
// produces — a typo in HOSTVEIL_AI_PROVIDER is a configuration error, not
// an unreachable server, and deserves to say so.
type unknownProvider struct{ name string }

func (unknownProvider) Available(context.Context) bool { return true }

func (u unknownProvider) Explain(context.Context, model.Finding, string) (string, error) {
	return "", fmt.Errorf("unknown HOSTVEIL_AI_PROVIDER %q (want ollama, anthropic, or openai)", u.name)
}

func (u unknownProvider) Advise(context.Context, []model.Finding, string) (string, error) {
	return "", fmt.Errorf("unknown HOSTVEIL_AI_PROVIDER %q (want ollama, anthropic, or openai)", u.name)
}
