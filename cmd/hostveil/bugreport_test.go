package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestGitHubCLIUsesInvokingUsersAuthenticationAfterSudo(t *testing.T) {
	env := map[string]string{
		"SUDO_USER": "operator",
		"SUDO_UID":  "1000",
	}
	getenv := func(name string) string { return env[name] }
	lookPath := func(name string) (string, error) {
		if name != "sudo" {
			t.Fatalf("lookPath(%q), want sudo", name)
		}
		return "/usr/bin/sudo", nil
	}

	program, args := githubCLIInvocation(
		"/usr/bin/gh", []string{"issue", "create"}, 0, getenv, lookPath,
	)
	if program != "/usr/bin/sudo" {
		t.Fatalf("program = %q, want sudo", program)
	}
	want := []string{"-H", "-u", "operator", "--", "/usr/bin/gh", "issue", "create"}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("args = %#v, want %#v", args, want)
	}
}

func TestGitHubCLIRunsDirectlyWithoutSudoCaller(t *testing.T) {
	lookedUp := false
	program, args := githubCLIInvocation(
		"/usr/bin/gh", []string{"issue", "create"}, 1000,
		func(string) string { return "" },
		func(string) (string, error) { lookedUp = true; return "", errors.New("unexpected") },
	)
	if lookedUp {
		t.Fatal("looked for sudo for an unprivileged process")
	}
	if program != "/usr/bin/gh" || !reflect.DeepEqual(args, []string{"issue", "create"}) {
		t.Fatalf("invocation = %q %#v", program, args)
	}
}

func TestSendBugReportFallsBackToReadableLocalFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("PATH", dir) // no gh
	t.Setenv("HOSTVEIL_GITHUB_TOKEN", "")
	t.Setenv("SUDO_USER", "")
	t.Setenv("SUDO_UID", "")
	t.Setenv("SUDO_GID", "")

	const bundle = "# hostveil bug report\n\nlocal only\n"
	if err := sendBugReport(context.Background(), bundle); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "hostveil-bugreport.md")
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != bundle {
		t.Fatalf("saved report = %q, want %q", data, bundle)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("saved report mode = %v, want 0600", fi.Mode().Perm())
	}
}

func TestBugreportOutputDoesNotSilentlyDisableSend(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("PATH", dir) // force the consented send onto the local fallback
	t.Setenv("HOSTVEIL_GITHUB_TOKEN", "")
	t.Setenv("HOSTVEIL_NO_SUDO", "1")
	t.Setenv("SUDO_USER", "")
	t.Setenv("SUDO_UID", "")
	t.Setenv("SUDO_GID", "")

	output := filepath.Join(dir, "chosen.md")
	if code := cmdBugreport(context.Background(), []string{"--output", output, "--send", "--yes"}); code != 0 {
		t.Fatalf("cmdBugreport exit = %d", code)
	}
	for _, path := range []string{output, filepath.Join(dir, "hostveil-bugreport.md")} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		if !strings.Contains(string(data), "# hostveil bug report") {
			t.Fatalf("%s does not contain a bug report", path)
		}
	}
}

func TestGitHubCLIDoesNotTrustSudoUserWithoutSudoUID(t *testing.T) {
	program, _ := githubCLIInvocation(
		"/usr/bin/gh", nil, 0,
		func(name string) string {
			if name == "SUDO_USER" {
				return "forged"
			}
			return ""
		},
		func(string) (string, error) { return "/usr/bin/sudo", nil },
	)
	if strings.Contains(program, "sudo") {
		t.Fatalf("program = %q; SUDO_USER without SUDO_UID is not a sudo invocation", program)
	}
}
