package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A password is asked for only once the arguments make sense.
//
// Elevation used to happen in run(), before dispatch and therefore before any
// subcommand had looked at what it was given. resolveCommand routes any
// leading flag to scan, which is root-benefiting, so `hostveil --theme
// no-such-theme` prompted for a password, took it, re-executed as root, and
// then exited 2 on a usage error. One typo, one password.
//
// The test runs the real binary with a stub `sudo` on PATH that writes a file
// if it is ever reached. A usage error must not reach it.
func TestABadFlagCostsNoPassword(t *testing.T) {
	bin := buildHostveil(t)
	dir := t.TempDir()
	marker := filepath.Join(dir, "sudo-was-called")
	stubSudo(t, dir, marker)

	for _, args := range [][]string{
		{"--no-such-flag"},         // routed to scan, which is root-benefiting
		{"scan", "--no-such-flag"}, // and named outright
		{"fix", "--no-such-flag"},
		{"serve", "--no-such-flag"},
	} {
		cmd := exec.Command(bin, args...)
		cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"))
		out, err := cmd.CombinedOutput()

		if _, statErr := os.Stat(marker); statErr == nil {
			t.Errorf("%v: sudo was invoked for a command that then failed on a usage error:\n%s", args, out)
			_ = os.Remove(marker)
		}
		if err == nil {
			t.Errorf("%v exited 0:\n%s", args, out)
		}
		if !strings.Contains(string(out), "no-such-flag") {
			t.Errorf("%v: the usage error does not name the bad flag:\n%s", args, out)
		}
	}
}

// And a command with sound arguments still elevates. Without this the test
// above passes just as well on a binary that never elevates at all.
func TestASoundCommandStillAsksForRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("already root; there is nothing to elevate to")
	}
	bin := buildHostveil(t)
	dir := t.TempDir()
	marker := filepath.Join(dir, "sudo-was-called")
	stubSudo(t, dir, marker)

	cmd := exec.Command(bin, "scan", "--only", "sysctl")
	cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	out, _ := cmd.CombinedOutput()

	if _, statErr := os.Stat(marker); statErr != nil {
		t.Errorf("a valid command did not elevate, so plain `hostveil` no longer behaves like `sudo hostveil`:\n%s", out)
	}
}

// Not being able to ask is not the same as not needing to ask.
//
// With no sudo on PATH the function returned in silence, so the operator found
// out they needed root one domain at a time, half way through a scan, from
// findings that read like a broken tool rather than a missing privilege. The
// two lines above it have always explained why hostveil is *asking*.
func TestAMissingSudoSaysSoRatherThanGoingQuiet(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("already root; elevation is not attempted at all")
	}
	bin := buildHostveil(t)
	empty := t.TempDir() // a PATH with no sudo in it

	cmd := exec.Command(bin, "scan", "--only", "sysctl")
	cmd.Env = append(os.Environ(), "PATH="+empty)
	out, _ := cmd.CombinedOutput()

	if !strings.Contains(string(out), "no sudo on PATH") {
		t.Errorf("hostveil ran unprivileged without saying why:\n%s", out)
	}
}

// Every subcommand goes through parseAndElevate, so the ordering above is a
// property of the program rather than of the one command a test happened to
// run. A command that called parseFlags directly would parse its flags and
// never elevate — which is the quieter half of the same defect.
func TestNoCommandParsesFlagsWithoutElevating(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var checked int
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || name == "parseflags.go" {
			continue
		}
		file, perr := parser.ParseFile(fset, name, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		checked++
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			id, ok := call.Fun.(*ast.Ident)
			if !ok || id.Name != "parseFlags" {
				return true
			}
			t.Errorf("%s calls parseFlags directly at %s; use parseAndElevate, or the command parses its flags and never asks for root",
				name, fset.Position(call.Pos()))
			return true
		})
	}
	if checked == 0 {
		t.Fatal("no command files were read; the walk is looking in the wrong place")
	}
}

func buildHostveil(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "hostveil")
	out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput()
	if err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

// stubSudo puts a `sudo` on PATH that records that it was reached and exits,
// so a test can tell an elevation attempt from an elevation.
func stubSudo(t *testing.T, dir, marker string) {
	t.Helper()
	script := "#!/bin/sh\ntouch " + marker + "\nexit 0\n"
	path := filepath.Join(dir, "sudo")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
}
