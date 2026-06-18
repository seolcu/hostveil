package ssh

import (
	"path/filepath"
	"testing"
	"time"
)

func nowish() time.Time { return time.Date(2026, 6, 18, 0, 0, 0, 0, time.UTC) }

func TestParse_EmptyAndComments(t *testing.T) {
	p, err := Parse("")
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(p.Settings) != 0 {
		t.Errorf("empty input produced %d settings", len(p.Settings))
	}

	p, _ = Parse("# comment\n\n# another\n")
	if len(p.Settings) != 0 {
		t.Errorf("comments produced %d settings", len(p.Settings))
	}
}

func TestParse_PermitRootLogin(t *testing.T) {
	in := "Port 22\nPermitRootLogin yes\n"
	p, err := Parse(in)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	got := p.settingsByKey()
	if got["permitrootlogin"] != "yes" {
		t.Errorf("permitrootlogin = %q, want yes", got["permitrootlogin"])
	}
}

func TestParse_PermitRootLogin_Overridden(t *testing.T) {
	in := "PermitRootLogin yes\nPermitRootLogin no\n"
	p, _ := Parse(in)
	got := p.settingsByKey()
	if got["permitrootlogin"] != "no" {
		t.Errorf("override: permitrootlogin = %q, want no", got["permitrootlogin"])
	}
}

func TestRules(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		wantRules []string
	}{
		{
			name:      "all_safe",
			input:     "PermitRootLogin no\nPasswordAuthentication no\nProtocol 2\n",
			wantRules: nil,
		},
		{
			name:      "root_login_allowed",
			input:     "PermitRootLogin yes\n",
			wantRules: []string{"ssh.permit_root_login.allow"},
		},
		{
			name:      "password_auth_enabled",
			input:     "PasswordAuthentication yes\n",
			wantRules: []string{"ssh.password_auth.only"},
		},
		{
			name:      "protocol_1",
			input:     "Protocol 1\n",
			wantRules: []string{"ssh.protocol.legacy"},
		},
		{
			name:      "protocol_1_and_2",
			input:     "Protocol 2,1\n",
			wantRules: []string{"ssh.protocol.legacy"},
		},
		{
			name:      "root_and_protocol_1",
			input:     "PermitRootLogin yes\nProtocol 1\n",
			wantRules: []string{"ssh.permit_root_login.allow", "ssh.protocol.legacy"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := Parse(tc.input)
			got := rules(p, "/etc/ssh/sshd_config", nowish())
			if len(got) != len(tc.wantRules) {
				t.Fatalf("got %d findings, want %d: %+v", len(got), len(tc.wantRules), got)
			}
			for i, want := range tc.wantRules {
				if got[i].RuleID != want {
					t.Errorf("finding[%d].RuleID = %q, want %q", i, got[i].RuleID, want)
				}
			}
		})
	}
}

func TestRunWithPath_MissingFile(t *testing.T) {
	dir := t.TempDir()
	res, err := runWithPath(nil, filepath.Join(dir, "does-not-exist"))
	if err != nil {
		t.Fatalf("runWithPath error: %v", err)
	}
	if res.Skipped == nil {
		t.Fatalf("expected Skipped, got findings=%v", res.Findings)
	}
	if res.Skipped.Reason != "not_applicable" {
		t.Errorf("Reason = %q, want not_applicable", res.Skipped.Reason)
	}
}

func TestTokenize_Quoted(t *testing.T) {
	got := tokenize(`key "value with spaces"`)
	want := []string{`key`, `"value with spaces"`}
	if len(got) != len(want) {
		t.Fatalf("tokenize = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("tokenize[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
