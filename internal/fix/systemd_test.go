package fix

import (
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

// The drop-in has to end up with exactly one assignment, in a [Service]
// section, whatever it started as.
//
// A bare directive outside a section is not a systemd override — systemd
// ignores it — and two assignments of the same key is not wrong so much as
// evidence of a tool that does not know what it has already done.
func TestTheDropInEndsWithOneAssignmentInTheRightSection(t *testing.T) {
	tr := setServiceDirective("NoNewPrivileges", "NoNewPrivileges=yes")

	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{
			// The ordinary case: the file is absent, so the finding fired.
			name: "no file at all",
			in:   "",
			want: "[Service]\nNoNewPrivileges=yes\n",
		},
		{
			name: "a drop-in with other settings",
			in:   "[Service]\nRestart=always\n",
			want: "[Service]\nRestart=always\nNoNewPrivileges=yes\n",
		},
		{
			// Applying a fix twice is not an error the operator should have
			// to avoid.
			name: "already says it",
			in:   "[Service]\nNoNewPrivileges=yes\n",
			want: "[Service]\nNoNewPrivileges=yes\n",
		},
		{
			// Replaced, not appended. systemd takes the last assignment so
			// appending would work and read as a tool that cannot see.
			name: "explicitly says no",
			in:   "[Service]\nNoNewPrivileges=no\n",
			want: "[Service]\nNoNewPrivileges=yes\n",
		},
		{
			name: "systemd's other spellings of the same line",
			in:   "[Service]\n  nonewprivileges = false\n",
			want: "[Service]\nNoNewPrivileges=yes\n",
		},
		{
			// A section has to be made. Without one the directive belongs to
			// nothing.
			name: "no [Service] section",
			in:   "[Unit]\nDescription=x\n",
			want: "[Unit]\nDescription=x\n\n[Service]\nNoNewPrivileges=yes\n",
		},
		{
			// Under [Service], not at the end of the file — the end of the
			// file is inside [Install], where systemd would ignore it. The
			// SSH domain learned this about Match blocks.
			name: "a section follows [Service]",
			in:   "[Service]\nRestart=always\n\n[Install]\nWantedBy=multi-user.target\n",
			want: "[Service]\nRestart=always\nNoNewPrivileges=yes\n\n[Install]\nWantedBy=multi-user.target\n",
		},
		{
			name: "no trailing newline",
			in:   "[Service]\nRestart=always",
			want: "[Service]\nRestart=always\nNoNewPrivileges=yes\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tr([]byte(tc.in))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Errorf("got:\n%q\nwant:\n%q", got, tc.want)
			}
			// Twice is the same as once, from every starting point.
			again, err := tr(got)
			if err != nil || string(again) != string(got) {
				t.Errorf("applying it twice changed the file:\n%q\n%q", got, again)
			}
			if n := strings.Count(strings.ToLower(string(got)), "nonewprivileges="); n != 1 {
				t.Errorf("%d assignments, want 1:\n%s", n, got)
			}
		})
	}
}

// The path travels with the finding rather than being recomputed here, so a
// finding without it is a bug worth failing on rather than a path to guess.
func TestTheFixRefusesAFindingThatCarriesNoPath(t *testing.T) {
	for _, tc := range []struct {
		name string
		f    model.Finding
	}{
		{"no drop-in path", model.NewFinding("systemd.no-new-privileges", "t", model.SeverityLow,
			model.SourceSystemd, model.RemediationReview, model.WithService("gitea.service"))},
		{"no unit", model.NewFinding("systemd.no-new-privileges", "t", model.SeverityLow,
			model.SourceSystemd, model.RemediationReview,
			model.WithMetadata("dropin", "/tmp/x.conf"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := buildSystemdNoNewPrivileges(tc.f); err == nil {
				t.Error("built a fix with nothing to write to")
			}
		})
	}
}

// The re-check after this fix will still report the finding, because the
// checker asks systemd for the effective configuration and systemd has not
// re-read the file. TakesEffectOn is what turns that from a silent lie into a
// sentence, so its absence would be the defect.
func TestTheFixSaysWhatHasToHappenForItToTakeEffect(t *testing.T) {
	f := model.NewFinding("systemd.no-new-privileges", "t", model.SeverityLow,
		model.SourceSystemd, model.RemediationReview,
		model.WithService("gitea.service"),
		model.WithMetadata("dropin", "/etc/systemd/system/gitea.service.d/50-hostveil.conf"))

	fx, err := buildSystemdNoNewPrivileges(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(fx); err != nil {
		t.Fatal(err)
	}
	a := fx.Actions[0]
	if !strings.Contains(a.TakesEffectOn, "daemon-reload") || !strings.Contains(a.TakesEffectOn, "gitea.service") {
		t.Errorf("TakesEffectOn = %q — it has to name the reload and the unit", a.TakesEffectOn)
	}
	if !a.CreateIfMissing {
		t.Error("the drop-in does not exist yet; without CreateIfMissing the fix fails on the read")
	}
	if a.Warning == "" {
		t.Error("a service that deliberately escalates stops coming back, and nothing says so")
	}
	if a.Path != "/etc/systemd/system/gitea.service.d/50-hostveil.conf" {
		t.Errorf("writes to %q, not the path the checker named", a.Path)
	}
}
