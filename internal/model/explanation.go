package model

// Explanation is the plain-language explanation of a finding. Plain is
// always populated deterministically from the finding itself; AI is
// filled only when the user opted in and a provider was reachable.
type Explanation struct {
	Plain   string `json:"plain"`
	AI      string `json:"ai,omitempty"`
	AIError string `json:"ai_error,omitempty"`
}
