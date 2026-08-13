package main

import "testing"

// The hint is the answer to "which address do I open?", and every part of it
// has to be right or the operator pastes a command that fails somewhere else.
func TestTheSSHHintForwardsTheDashboardsOwnPort(t *testing.T) {
	env := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}
	for _, tc := range []struct {
		name string
		vars map[string]string
		addr string
		want string
	}{
		{
			name: "an ordinary session",
			vars: map[string]string{"SSH_CONNECTION": "10.0.0.9 51234 10.0.0.2 22", "SUDO_USER": "seolcu"},
			addr: "127.0.0.1:8787",
			want: "ssh -N -L 8787:127.0.0.1:8787 seolcu@10.0.0.2",
		},
		{
			// serve elevates, so by the time this runs the process is root.
			// Recommending root@ would recommend the login hostveil reports
			// as a finding.
			name: "the login name, not the elevated one",
			vars: map[string]string{"SSH_CONNECTION": "10.0.0.9 51234 10.0.0.2 22",
				"SUDO_USER": "seolcu", "USER": "root"},
			addr: "127.0.0.1:8787",
			want: "ssh -N -L 8787:127.0.0.1:8787 seolcu@10.0.0.2",
		},
		{
			name: "a non-default sshd port",
			vars: map[string]string{"SSH_CONNECTION": "10.0.0.9 51234 10.0.0.2 2222", "USER": "ops"},
			addr: "127.0.0.1:8787",
			want: "ssh -N -p 2222 -L 8787:127.0.0.1:8787 ops@10.0.0.2",
		},
		{
			name: "a dashboard on a different port",
			vars: map[string]string{"SSH_CONNECTION": "10.0.0.9 51234 10.0.0.2 22", "USER": "ops"},
			addr: "127.0.0.1:9999",
			want: "ssh -N -L 9999:127.0.0.1:9999 ops@10.0.0.2",
		},
		{
			name: "IPv6 is bracketed",
			vars: map[string]string{"SSH_CONNECTION": "2001:db8::9 51234 2001:db8::2 22", "USER": "ops"},
			addr: "127.0.0.1:8787",
			want: "ssh -N -L 8787:127.0.0.1:8787 ops@[2001:db8::2]",
		},
		{
			name: "not an SSH session at all",
			vars: map[string]string{"USER": "ops"},
			addr: "127.0.0.1:8787",
			want: "",
		},
		{
			// A shell that exports the name without the value, or a variable
			// somebody set by hand. A hint built from half of it would name a
			// host that is not there.
			name: "a truncated SSH_CONNECTION",
			vars: map[string]string{"SSH_CONNECTION": "10.0.0.9 51234", "USER": "ops"},
			addr: "127.0.0.1:8787",
			want: "",
		},
		{
			name: "a server field that is not an address",
			vars: map[string]string{"SSH_CONNECTION": "10.0.0.9 51234 not-an-ip 22", "USER": "ops"},
			addr: "127.0.0.1:8787",
			want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sshHint(env(tc.vars), tc.addr); got != tc.want {
				t.Errorf("sshHint = %q, want %q", got, tc.want)
			}
		})
	}
}
