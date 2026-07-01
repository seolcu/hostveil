package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAllowedHostsFor(t *testing.T) {
	cases := []struct {
		name     string
		bindAddr string
		want     map[string]bool // nil means "no restriction (skip check)"
	}{
		{
			name:     "loopback default accepts localhost aliases",
			bindAddr: "127.0.0.1:8787",
			want: map[string]bool{
				"127.0.0.1:8787": true,
				"[::1]:8787":     true,
				"localhost:8787": true,
			},
		},
		{
			name:     "ipv6 loopback accepts the same aliases",
			bindAddr: "[::1]:8787",
			want: map[string]bool{
				"127.0.0.1:8787": true,
				"[::1]:8787":     true,
				"localhost:8787": true,
			},
		},
		{
			name:     "specific LAN IP is exact-match only, no localhost alias",
			bindAddr: "192.168.1.50:8787",
			want:     map[string]bool{"192.168.1.50:8787": true},
		},
		{
			name:     "wildcard 0.0.0.0 disables the check (operator opted into exposure)",
			bindAddr: "0.0.0.0:8787",
			want:     nil,
		},
		{
			name:     "wildcard :: disables the check",
			bindAddr: "[::]:8787",
			want:     nil,
		},
		{
			name:     "bare :PORT (empty host) disables the check",
			bindAddr: ":8787",
			want:     nil,
		},
		{
			name:     "malformed address disables the check rather than panicking",
			bindAddr: "not-a-valid-addr",
			want:     nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := allowedHostsFor(c.bindAddr)
			if (got == nil) != (c.want == nil) {
				t.Fatalf("allowedHostsFor(%q) = %v, want nil-ness %v", c.bindAddr, got, c.want == nil)
			}
			if c.want == nil {
				return
			}
			if len(got) != len(c.want) {
				t.Errorf("allowedHostsFor(%q) = %v, want %v", c.bindAddr, got, c.want)
			}
			for k := range c.want {
				if !got[k] {
					t.Errorf("allowedHostsFor(%q) missing expected host %q, got %v", c.bindAddr, k, got)
				}
			}
		})
	}
}

// TestHostGuard_RejectsDNSRebinding is the core regression test: it
// simulates the exact scenario sameOrigin(Origin, r.Host) cannot catch —
// a request whose Origin and Host headers both read as an
// attacker-controlled domain, because DNS rebinding happened before the
// browser made the request. sameOrigin would allow this (Origin == Host),
// but hostGuard must reject it because the Host header itself does not
// match how this server was actually bound.
func TestHostGuard_RejectsDNSRebinding(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	guarded := hostGuard("127.0.0.1:8787", inner)

	req := httptest.NewRequest("GET", "/api/result", nil)
	req.Host = "sub.attacker.example" // rebound domain, no port — browsers omit :80
	req.Header.Set("Origin", "http://sub.attacker.example")

	rec := httptest.NewRecorder()
	guarded.ServeHTTP(rec, req)

	if called {
		t.Error("hostGuard called the inner handler for a rebound Host header — DNS rebinding would succeed")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

// TestHostGuard_RejectsRebindingEvenWhenOriginMatchesHost is the specific
// case that defeats sameOrigin: after a successful DNS rebind, the
// browser's request has Origin == "http://" + Host, both reading as the
// attacker's domain. A check that only compares Origin against Host
// (like sameOrigin) sees them match and would allow the request through.
func TestHostGuard_RejectsRebindingEvenWhenOriginMatchesHost(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	guarded := hostGuard("127.0.0.1:8787", inner)

	req := httptest.NewRequest("GET", "/api/result", nil)
	req.Host = "attacker.example:8787"
	req.Header.Set("Origin", "http://attacker.example:8787")

	// Confirm the premise: sameOrigin considers this a match (this is
	// exactly why it cannot defend against DNS rebinding on its own).
	if !sameOrigin(req.Header.Get("Origin"), req.Host) {
		t.Fatal("test premise broken: sameOrigin should consider Origin==Host a match")
	}

	rec := httptest.NewRecorder()
	guarded.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d (hostGuard must reject even though sameOrigin would accept)", rec.Code, http.StatusForbidden)
	}
}

func TestHostGuard_AllowsLegitimateLoopbackAccess(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	guarded := hostGuard("127.0.0.1:8787", inner)

	for _, host := range []string{"127.0.0.1:8787", "localhost:8787", "LOCALHOST:8787"} {
		t.Run(host, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/result", nil)
			req.Host = host
			rec := httptest.NewRecorder()
			guarded.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Errorf("host %q rejected (status %d), want 200", host, rec.Code)
			}
		})
	}
}

func TestHostGuard_RejectsWrongPortOnLoopback(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	guarded := hostGuard("127.0.0.1:8787", inner)

	req := httptest.NewRequest("GET", "/api/result", nil)
	req.Host = "127.0.0.1:9999" // right host, wrong port
	rec := httptest.NewRecorder()
	guarded.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d for mismatched port", rec.Code, http.StatusForbidden)
	}
}

func TestHostGuard_PassthroughOnWildcardBind(t *testing.T) {
	// A wildcard bind (0.0.0.0) is the operator's explicit choice to
	// expose the service beyond localhost (see the non-local bind
	// warning); hostGuard must not add its own hostname allowlist on
	// top of that, since there is no fixed set of valid hostnames for a
	// LAN/public-reachable listener.
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	guarded := hostGuard("0.0.0.0:8787", inner)

	req := httptest.NewRequest("GET", "/api/result", nil)
	req.Host = "anything.example:8787"
	rec := httptest.NewRecorder()
	guarded.ServeHTTP(rec, req)

	if !called {
		t.Error("hostGuard should pass through on a wildcard bind")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 on wildcard bind passthrough", rec.Code)
	}
}

// TestHostGuard_UnprotectedEndpointNowCovered documents the motivating
// bug: GET /api/result had no Origin check at all (unlike POST /api/fix
// etc.), making it a pure DNS-rebinding target for exfiltrating the full
// scan snapshot (findings, evidence, hostname, local IP). hostGuard is
// applied globally in Serve(), so this endpoint is covered without
// needing its own per-handler check.
func TestHostGuard_UnprotectedEndpointNowCovered(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/result", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"findings":[]}`))
	})
	guarded := hostGuard("127.0.0.1:8787", mux)

	req := httptest.NewRequest("GET", "/api/result", nil)
	req.Host = "rebind.attacker.example"
	rec := httptest.NewRecorder()
	guarded.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("GET /api/result under a rebound Host = %d, want %d", rec.Code, http.StatusForbidden)
	}
}
