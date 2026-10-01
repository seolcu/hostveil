package core

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/seolcu/hostveil/internal/history"
	"github.com/seolcu/hostveil/internal/model"
)

// exitErr returns a real *exec.ExitError with the given status, so the
// classifier is tested against what the runner actually hands back rather
// than a hand-made stand-in it might not recognise.
func exitErr(t *testing.T, code int) error {
	t.Helper()
	err := exec.Command("sh", "-c", "exit "+strconv.Itoa(code)).Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("could not produce an exit status %d: %v", code, err)
	}
	return err
}

type answer struct {
	out []byte
	err error
}

// fleetRunner answers each host's ssh argv from a table, keyed by the host,
// and records how many ran at once.
type fleetRunner struct {
	mu      sync.Mutex
	answers map[string]answer
	argv    map[string][]string
	running atomic.Int32
	maxSeen atomic.Int32
	hold    time.Duration
}

func (r *fleetRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	n := r.running.Add(1)
	defer r.running.Add(-1)
	for {
		m := r.maxSeen.Load()
		if n <= m || r.maxSeen.CompareAndSwap(m, n) {
			break
		}
	}
	time.Sleep(r.hold)
	full := append([]string{name}, args...)
	host := ""
	for i, a := range full {
		if a == "--" && i+1 < len(full) {
			host = full[i+1]
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.argv == nil {
		r.argv = map[string][]string{}
	}
	r.argv[host] = full
	a, ok := r.answers[host]
	if !ok {
		return nil, errors.New("unscripted host " + host)
	}
	return a.out, a.err
}

func (*fleetRunner) LookPath(name string) (string, error) { return "/usr/bin/" + name, nil }

func reportJSON(t *testing.T, overall uint8, findings ...model.Finding) []byte {
	t.Helper()
	r := model.Report{
		Findings: findings,
		Score:    model.ScoreBreakdown{Overall: overall, Applicable: true},
		Domains:  []model.DomainResult{{Source: model.SourceSSH, State: model.ScanDone}},
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fleetEngine(r *fleetRunner, t *testing.T) *Engine {
	return New(Config{Runner: r, Store: history.NewStore(t.TempDir())})
}

func TestFleetReadsEveryAnswer(t *testing.T) {
	high := model.NewFinding("ssh.rootlogin", "root login", model.SeverityHigh, model.SourceSSH, model.RemediationReview)
	r := &fleetRunner{answers: map[string]answer{
		"clean": {reportJSON(t, 96), nil},
		// scan exits 1 on a High finding and 3 on a failed domain, and both
		// come with a complete report. Neither is a failed host.
		"has-high":    {reportJSON(t, 41, high), exitErr(t, 1)},
		"incomplete":  {reportJSON(t, 70), exitErr(t, 3)},
		"unreachable": {nil, exitErr(t, 255)},
		"no-hostveil": {nil, exitErr(t, 127)},
		"not-json":    {[]byte("hello\n"), nil},
	}}
	hosts := []string{"clean", "has-high", "incomplete", "unreachable", "no-hostveil", "not-json"}
	f := fleetEngine(r, t).Fleet(context.Background(), hosts, FleetOptions{})

	for i, h := range hosts {
		if f.Hosts[i].Host != h {
			t.Fatalf("order changed: %d is %q, want %q", i, f.Hosts[i].Host, h)
		}
	}
	get := func(h string) model.FleetEntry {
		for _, e := range f.Hosts {
			if e.Host == h {
				return e
			}
		}
		t.Fatalf("no entry for %s", h)
		return model.FleetEntry{}
	}
	for _, h := range []string{"clean", "has-high", "incomplete"} {
		if e := get(h); e.Report == nil || e.Error != "" {
			t.Errorf("%s: want a report, got error %q", h, e.Error)
		}
	}
	if got := get("has-high").Report.Findings; len(got) != 1 || got[0].ID != "ssh.rootlogin" {
		t.Errorf("has-high findings = %v", got)
	}
	for h, want := range map[string]string{
		"unreachable": "could not connect over SSH",
		"no-hostveil": "not installed",
		"not-json":    "not a hostveil report",
	} {
		e := get(h)
		if e.Report != nil || !strings.Contains(e.Error, want) {
			t.Errorf("%s: want error containing %q, got report=%v error=%q", h, want, e.Report != nil, e.Error)
		}
	}
}

// ssh reads its arguments before it knows which is the destination, so a
// "host" beginning with '-' is an option — -oProxyCommand runs a local
// command. It must never reach the runner at all.
func TestFleetRefusesAHostSshWouldReadAsAnOption(t *testing.T) {
	r := &fleetRunner{answers: map[string]answer{"ok": {reportJSON(t, 90), nil}}}
	f := fleetEngine(r, t).Fleet(context.Background(), []string{"-oProxyCommand=touch /tmp/x", "ok", "two words"}, FleetOptions{})
	if f.Hosts[0].Error == "" || f.Hosts[2].Error == "" {
		t.Errorf("unsafe hosts were not refused: %+v", f.Hosts)
	}
	if _, ran := r.argv["-oProxyCommand=touch /tmp/x"]; ran {
		t.Error("an option-shaped host reached ssh")
	}
	if f.Hosts[1].Report == nil {
		t.Error("a valid host beside a refused one must still be scanned")
	}
}

func TestFleetArgv(t *testing.T) {
	r := &fleetRunner{answers: map[string]answer{"web1": {reportJSON(t, 90), nil}, "db1": {reportJSON(t, 90), nil}}}
	e := fleetEngine(r, t)
	e.Fleet(context.Background(), []string{"web1"}, FleetOptions{})
	e.Fleet(context.Background(), []string{"db1"}, FleetOptions{Sudo: true})

	plain := strings.Join(r.argv["web1"], " ")
	for _, want := range []string{"BatchMode=yes", "-- web1", "HOSTVEIL_NO_SUDO=1 hostveil scan --json"} {
		if !strings.Contains(plain, want) {
			t.Errorf("argv %q lacks %q", plain, want)
		}
	}
	if s := strings.Join(r.argv["db1"], " "); !strings.Contains(s, "-- db1 sudo -n hostveil scan --json") {
		t.Errorf("--sudo argv = %q", s)
	}
}

func TestFleetSudoNeedsAPassword(t *testing.T) {
	err := errors.Join(exitErr(t, 1), errors.New("sudo: a password is required"))
	r := &fleetRunner{answers: map[string]answer{"h": {nil, err}}}
	f := fleetEngine(r, t).Fleet(context.Background(), []string{"h"}, FleetOptions{Sudo: true})
	if !strings.Contains(f.Hosts[0].Error, "NOPASSWD") {
		t.Errorf("error = %q", f.Hosts[0].Error)
	}
}

func TestFleetBoundsConcurrency(t *testing.T) {
	answers := map[string]answer{}
	var hosts []string
	for _, h := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		answers[h] = answer{reportJSON(t, 90), nil}
		hosts = append(hosts, h)
	}
	r := &fleetRunner{answers: answers, hold: 20 * time.Millisecond}
	fleetEngine(r, t).Fleet(context.Background(), hosts, FleetOptions{Parallel: 2})
	if got := r.maxSeen.Load(); got > 2 {
		t.Errorf("%d scans ran at once, want at most 2", got)
	}
}

func TestWorstFirst(t *testing.T) {
	rep := func(score uint8, applicable bool) *model.Report {
		return &model.Report{Score: model.ScoreBreakdown{Overall: score, Applicable: applicable}}
	}
	f := model.Fleet{Hosts: []model.FleetEntry{
		{Host: "good", Report: rep(90, true)},
		{Host: "na", Report: rep(0, false)},
		{Host: "down", Error: "could not connect"},
		{Host: "bad", Report: rep(30, true)},
	}}
	var got []string
	for _, e := range f.WorstFirst() {
		got = append(got, e.Host)
	}
	if strings.Join(got, ",") != "down,bad,good,na" {
		t.Errorf("WorstFirst = %v", got)
	}
}
