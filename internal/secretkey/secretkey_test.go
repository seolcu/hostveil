package secretkey

import "testing"

func TestMatchesIsCaseInsensitiveAndSubstring(t *testing.T) {
	hits := []string{
		"password", "PASSWORD", "DB_PASSWORD", "mysql_root_passwd",
		"SECRET", "app_secret_key", "API_KEY", "apiKeyProd", "APIKEY",
		"GITHUB_TOKEN", "access_token", "SSH_PRIVATE_KEY", "AWS_ACCESS_KEY_ID",
	}
	for _, k := range hits {
		if !Matches(k) {
			t.Errorf("Matches(%q) = false, want true", k)
		}
	}

	misses := []string{
		"", "PATH", "HOSTNAME", "TZ", "PUID", "LOG_LEVEL",
		"DATABASE_URL", "PORT", "NODE_ENV",
	}
	for _, k := range misses {
		if Matches(k) {
			t.Errorf("Matches(%q) = true, want false", k)
		}
	}
}

// A config that references a secret instead of containing one is the correct
// pattern; treating it as a leak would penalize doing the right thing.
func TestLooksLiteralRejectsReferencesAndPlaceholders(t *testing.T) {
	cases := []struct {
		value string
		want  bool
		why   string
	}{
		{"hunter2again", true, "a plain literal value"},
		{"${DB_PASSWORD}", false, "interpolation reference"},
		{"$$escaped", false, "escaped reference"},
		{"", false, "empty"},
		{"abc", false, "too short to be a real secret"},
		{"abcde", false, "five chars is still under the threshold"},
		{"abcdef", true, "six chars is the threshold"},
	}
	for _, c := range cases {
		if got := LooksLiteral(c.value); got != c.want {
			t.Errorf("LooksLiteral(%q) = %v, want %v — %s", c.value, got, c.want, c.why)
		}
	}
}
