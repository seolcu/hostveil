// Package secretkey holds the shared heuristic for deciding that a
// configuration key names a credential, and that its value looks like a real
// one rather than a placeholder.
//
// It is deliberately name-based. hostveil has to judge a value sensitive
// without ever recording the value itself: findings are rendered by every UI
// and persisted to disk, so a checker that quoted the secret it found would
// leak it into exactly the places a secret must not reach. Matching on the
// key name means the value is only ever measured, never kept.
package secretkey

import "strings"

// Patterns are the substrings that mark a key as naming a credential. They
// are matched case-insensitively against the whole key, so "DB_PASSWORD" and
// "apiKeyProd" both hit.
var Patterns = []string{
	"password", "passwd", "secret", "api_key", "apikey",
	"token", "private_key", "access_key",
}

// Matches reports whether key names a credential. Callers pass the key as
// written; case folding happens here.
func Matches(key string) bool {
	lower := strings.ToLower(key)
	for _, p := range Patterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// LooksLiteral reports whether a value for a credential-named key looks like
// a real secret rather than a reference to one.
//
// Interpolation references ("${DB_PASSWORD}", "$$escaped") are how a config
// is *supposed* to name a secret it does not contain, so flagging them would
// penalize the correct pattern. Very short values are placeholders,
// disabled-by-empty-string markers, or too weak for the finding to be about
// leakage. Both exclusions exist to keep a "you have a hardcoded secret"
// finding from firing on configs that do not.
func LooksLiteral(value string) bool {
	if value == "" || strings.HasPrefix(value, "${") || strings.HasPrefix(value, "$$") {
		return false
	}
	return len(value) >= 6
}
