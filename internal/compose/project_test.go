package compose

import "testing"

func TestPortParsing(t *testing.T) {
	cases := []struct {
		in            string
		hostIP        string
		hostPort      string
		containerPort string
		published     bool
		exposedAll    bool
	}{
		{"80", "", "", "80", false, false},
		{"8080:80", "", "8080", "80", true, true},
		{"127.0.0.1:8080:80", "127.0.0.1", "8080", "80", true, false},
		{"0.0.0.0:8080:80", "0.0.0.0", "8080", "80", true, true},
		{"127.0.0.1:5432:5432/tcp", "127.0.0.1", "5432", "5432", true, false},
	}
	for _, tc := range cases {
		var p Port
		if err := p.parseShort(tc.in); err != nil {
			t.Fatalf("parseShort(%q): %v", tc.in, err)
		}
		if p.HostIP != tc.hostIP || p.HostPort != tc.hostPort || p.ContainerPort != tc.containerPort || p.Published != tc.published {
			t.Errorf("parseShort(%q) = %+v", tc.in, p)
		}
		if got := p.ExposedOnAllInterfaces(); got != tc.exposedAll {
			t.Errorf("%q ExposedOnAllInterfaces = %v, want %v", tc.in, got, tc.exposedAll)
		}
	}
}

func TestVolumeParsing(t *testing.T) {
	cases := []struct {
		in       string
		source   string
		target   string
		readOnly bool
		bind     bool
	}{
		{"/etc:/host/etc", "/etc", "/host/etc", false, true},
		{"/etc:/host/etc:ro", "/etc", "/host/etc", true, true},
		{"named:/data", "named", "/data", false, false},
		{"./local:/app", "./local", "/app", false, true},
	}
	for _, tc := range cases {
		var v Volume
		if err := v.parseShort(tc.in); err != nil {
			t.Fatalf("parseShort(%q): %v", tc.in, err)
		}
		if v.Source != tc.source || v.Target != tc.target || v.ReadOnly != tc.readOnly || v.Bind != tc.bind {
			t.Errorf("parseShort(%q) = %+v", tc.in, v)
		}
	}
}

func TestParseInvalidYAMLErrors(t *testing.T) {
	if _, err := Parse("bad.yml", []byte("services: [::::")); err == nil {
		t.Error("expected error on malformed YAML")
	}
}

// FuzzParse ensures parsing arbitrary bytes never panics — compose files
// come from the host and may be malformed or hostile.
func FuzzParse(f *testing.F) {
	f.Add([]byte("services:\n  a:\n    image: x\n"))
	f.Add([]byte("services:\n  a:\n    ports:\n      - \"8080:80\"\n"))
	f.Add([]byte("not yaml at all: ["))
	f.Fuzz(func(t *testing.T, data []byte) {
		proj, err := Parse("fuzz.yml", data)
		if err != nil {
			return
		}
		// If it parsed, auditing must also not panic; exercise accessors.
		for _, svc := range proj.Services {
			for _, p := range svc.Ports {
				_ = p.ExposedOnAllInterfaces()
			}
		}
	})
}
