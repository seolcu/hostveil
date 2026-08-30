package ai

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestFromEnvDefaultsToOllama(t *testing.T) {
	t.Setenv("HOSTVEIL_AI_PROVIDER", "")
	e := FromEnv()
	if _, ok := e.(*Ollama); !ok {
		t.Errorf("FromEnv() = %T, want *Ollama when HOSTVEIL_AI_PROVIDER is unset — nothing should leave the host by default", e)
	}
}

func TestFromEnvSelectsByName(t *testing.T) {
	cases := map[string]any{
		"ollama":    &Ollama{},
		"anthropic": &Anthropic{},
		"openai":    &OpenAICompat{},
	}
	for name, want := range cases {
		t.Setenv("HOSTVEIL_AI_PROVIDER", name)
		got := FromEnv()
		if reflect.TypeOf(got) != reflect.TypeOf(want) {
			t.Errorf("FromEnv() with HOSTVEIL_AI_PROVIDER=%q = %T, want %T", name, got, want)
		}
	}
}

func TestFromEnvNamesTheBadValueRatherThanSilentlyFallingBack(t *testing.T) {
	t.Setenv("HOSTVEIL_AI_PROVIDER", "chatgpt")
	e := FromEnv()
	if !e.Available(context.Background()) {
		t.Fatal("unknownProvider must report Available so Explain actually runs and surfaces the bad value")
	}
	_, err := e.Explain(context.Background(), finding(), "")
	if err == nil || !strings.Contains(err.Error(), "chatgpt") {
		t.Errorf("Explain error = %v, want it to name the misconfigured value", err)
	}
}
