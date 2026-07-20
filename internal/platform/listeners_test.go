package platform

import (
	"context"
	"errors"
	"testing"
)

type ssRunner struct {
	out string
	err error
}

func (ssRunner) LookPath(name string) (string, error) { return "/usr/bin/" + name, nil }
func (r ssRunner) Run(_ context.Context, _ string, _ ...string) ([]byte, error) {
	return []byte(r.out), r.err
}

const ssSample = `State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
LISTEN 0      511          0.0.0.0:80        0.0.0.0:*     users:(("nginx",pid=101,fd=6))
LISTEN 0      511        127.0.0.1:6379      0.0.0.0:*     users:(("redis-server",pid=999,fd=6))
LISTEN 0      128             [::]:22           [::]:*     users:(("sshd",pid=77,fd=4))
LISTEN 0      128     [fe80::1%lo]:5432         [::]:*     users:(("postgres",pid=88,fd=5))
LISTEN 0      128            *:18789               *:*
garbage
`

func TestListenersParsesSsOutput(t *testing.T) {
	ls, err := Listeners(context.Background(), ssRunner{out: ssSample})
	if err != nil {
		t.Fatal(err)
	}
	if len(ls) != 5 {
		t.Fatalf("parsed %d listeners, want 5: %+v", len(ls), ls)
	}

	want := []Listener{
		{Addr: "0.0.0.0", Port: 80, Proc: "nginx"},
		{Addr: "127.0.0.1", Port: 6379, Proc: "redis-server"},
		{Addr: "::", Port: 22, Proc: "sshd"},
		{Addr: "fe80::1%lo", Port: 5432, Proc: "postgres"},
		// No process column at all: -p output is absent without root.
		{Addr: "*", Port: 18789, Proc: ""},
	}
	for i, w := range want {
		if ls[i] != w {
			t.Errorf("listener %d = %+v, want %+v", i, ls[i], w)
		}
	}
}

// The header row and unparseable junk are skipped, never surfaced as an
// error — one odd line must not cost us the whole socket table.
func TestListenersSkipsHeaderAndGarbage(t *testing.T) {
	ls, err := Listeners(context.Background(), ssRunner{out: "State Recv-Q Send-Q Local\nnonsense\n\n"})
	if err != nil {
		t.Fatal(err)
	}
	if len(ls) != 0 {
		t.Errorf("got %d listeners, want none: %+v", len(ls), ls)
	}
}

func TestListenersPropagatesRunError(t *testing.T) {
	_, err := Listeners(context.Background(), ssRunner{err: errors.New("ss: not found")})
	if err == nil {
		t.Fatal("expected the runner error to propagate")
	}
}

// Only genuine loopback addresses are host-only. The wildcards are the whole
// point of the check: 0.0.0.0 and :: mean "every interface".
func TestLoopbackClassification(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1", true},
		{"127.0.0.53", true},
		{"::1", true},
		{"::1%lo", true}, // zone suffix must be stripped before parsing
		{"0.0.0.0", false},
		{"::", false},
		{"*", false},
		{"192.168.1.10", false},
		{"fe80::1%eth0", false},
		{"", false},
	}
	for _, c := range cases {
		if got := (Listener{Addr: c.addr}).Loopback(); got != c.want {
			t.Errorf("Listener{Addr: %q}.Loopback() = %v, want %v", c.addr, got, c.want)
		}
	}
}
