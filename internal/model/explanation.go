package model

// Explanation is the plain-language explanation of a finding. Plain is
// always populated deterministically from the finding itself; AI is
// filled only when the user opted in and a provider was reachable.
type Explanation struct {
	Plain   string `json:"plain"`
	AI      string `json:"ai,omitempty"`
	AIError string `json:"ai_error,omitempty"`
}

// Advice is the same shape as Explanation, for a whole set of findings at
// once rather than one: Plain is a deterministic listing of every active
// fixable finding's Benefit/SideEffect, always available with no AI
// required; AI is a situational verdict across all of them when the
// operator opted in and a provider was reachable.
type Advice struct {
	Plain   string `json:"plain"`
	AI      string `json:"ai,omitempty"`
	AIError string `json:"ai_error,omitempty"`
}
