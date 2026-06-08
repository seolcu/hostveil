package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/scan"
)

func TestHasFlag(t *testing.T) {
	tests := []struct {
		args []string
		name string
		want bool
	}{
		{[]string{"cmd"}, "--foo", false},
		{[]string{"cmd", "--foo"}, "--foo", true},
		{[]string{"cmd", "--bar", "--foo"}, "--foo", true},
		{[]string{"cmd", "--foo", "value"}, "--foo", true},
		{[]string{"cmd"}, "--no-update", false},
		{[]string{"cmd", "--no-update"}, "--no-update", true},
	}
	for _, tt := range tests {
		got := hasFlag(tt.args, tt.name)
		if got != tt.want {
			t.Errorf("hasFlag(%v, %q) = %v, want %v", tt.args, tt.name, got, tt.want)
		}
	}
}

func TestScanningMessage(t *testing.T) {
	tests := []struct {
		tool string
		want string
	}{
		{"trivy", "Scanning container images..."},
		{"lynis", "Auditing system hardening..."},
		{"unknown", "Scanning..."},
		{"", "Scanning..."},
	}
	for _, tt := range tests {
		got := scan.ScanningMessage(tt.tool)
		if got != tt.want {
			t.Errorf("ScanningMessage(%q) = %q, want %q", tt.tool, got, tt.want)
		}
	}
}

func TestHelpText(t *testing.T) {
	text := helpText()
	if !strings.Contains(text, "hostveil") {
		t.Error("helpText should contain 'hostveil'")
	}
	if !strings.Contains(text, "serve") {
		t.Error("helpText should contain 'serve'")
	}
	if !strings.Contains(text, "setup") {
		t.Error("helpText should contain 'setup'")
	}
}

func TestCheckLatestVersion(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"tag_name": "v1.2.3"}`))
	}))
	defer ts.Close()

	oldURL := checkLatestURL
	oldClient := httpClient
	defer func() {
		checkLatestURL = oldURL
		httpClient = oldClient
	}()

	checkLatestURL = ts.URL
	httpClient = ts.Client()

	version, err := checkLatestVersion()
	if err != nil {
		t.Fatalf("checkLatestVersion() returned error: %v", err)
	}
	if version != "1.2.3" {
		t.Errorf("checkLatestVersion() = %q, want %q", version, "1.2.3")
	}
}

func TestCheckLatestVersion_EmptyTag(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"tag_name": ""}`))
	}))
	defer ts.Close()

	oldURL := checkLatestURL
	oldClient := httpClient
	defer func() {
		checkLatestURL = oldURL
		httpClient = oldClient
	}()

	checkLatestURL = ts.URL
	httpClient = ts.Client()

	version, err := checkLatestVersion()
	if err != nil {
		t.Fatalf("checkLatestVersion() returned error: %v", err)
	}
	if version != "" {
		t.Errorf("checkLatestVersion() = %q, want empty", version)
	}
}

func TestCheckLatestVersion_HTTPError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	oldURL := checkLatestURL
	oldClient := httpClient
	defer func() {
		checkLatestURL = oldURL
		httpClient = oldClient
	}()

	checkLatestURL = ts.URL
	httpClient = ts.Client()

	_, err := checkLatestVersion()
	if err == nil {
		t.Error("checkLatestVersion() should return error for HTTP 500")
	}
}

func TestCheckLatestVersion_BadJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`not json`))
	}))
	defer ts.Close()

	oldURL := checkLatestURL
	oldClient := httpClient
	defer func() {
		checkLatestURL = oldURL
		httpClient = oldClient
	}()

	checkLatestURL = ts.URL
	httpClient = ts.Client()

	_, err := checkLatestVersion()
	if err == nil {
		t.Error("checkLatestVersion() should return error for bad JSON")
	}
}

func TestCheckLatestVersion_NetworkError(t *testing.T) {
	oldURL := checkLatestURL
	oldClient := httpClient
	defer func() {
		checkLatestURL = oldURL
		httpClient = oldClient
	}()

	checkLatestURL = "http://127.0.0.1:1/"
	httpClient = &http.Client{}

	_, err := checkLatestVersion()
	if err == nil {
		t.Error("checkLatestVersion() should return error for unreachable host")
	}
}

type errReader struct{}

func (errReader) Read(p []byte) (n int, err error) {
	return 0, io.ErrUnexpectedEOF
}

func (errReader) Close() error {
	return nil
}

func TestCheckLatestVersion_ReadError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"tag_name": "v1.0.0"}`))
	}))
	defer ts.Close()

	oldURL := checkLatestURL
	oldClient := httpClient
	defer func() {
		checkLatestURL = oldURL
		httpClient = oldClient
	}()

	checkLatestURL = ts.URL
	httpClient = ts.Client()

	version, err := checkLatestVersion()
	if err != nil {
		t.Fatalf("checkLatestVersion() returned error: %v", err)
	}
	if version != "1.0.0" {
		t.Errorf("checkLatestVersion() = %q, want %q", version, "1.0.0")
	}
}

func TestRunSetup_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("#!/bin/sh\necho hello\n"))
	}))
	defer ts.Close()

	oldURL := installerURL
	oldClient := httpClient
	defer func() {
		installerURL = oldURL
		httpClient = oldClient
	}()

	installerURL = ts.URL
	httpClient = ts.Client()

	err := runSetup()
	if err != nil {
		t.Fatalf("runSetup() returned error: %v", err)
	}
}

func TestRunSetup_HTTPError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	oldURL := installerURL
	oldClient := httpClient
	defer func() {
		installerURL = oldURL
		httpClient = oldClient
	}()

	installerURL = ts.URL
	httpClient = ts.Client()

	err := runSetup()
	if err == nil {
		t.Fatal("runSetup() should return error for HTTP 404")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("runSetup() error should mention status code, got: %v", err)
	}
}

func TestRunSetup_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	oldURL := installerURL
	oldClient := httpClient
	defer func() {
		installerURL = oldURL
		httpClient = oldClient
	}()

	installerURL = ts.URL
	httpClient = ts.Client()

	err := runSetup()
	if err == nil {
		t.Fatal("runSetup() should return error for HTTP 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("runSetup() error should mention status code, got: %v", err)
	}
}

func TestRunSetup_NetworkError(t *testing.T) {
	oldURL := installerURL
	oldClient := httpClient
	defer func() {
		installerURL = oldURL
		httpClient = oldClient
	}()

	installerURL = "http://127.0.0.1:1/"
	httpClient = &http.Client{}

	err := runSetup()
	if err == nil {
		t.Error("runSetup() should return error for unreachable host")
	}
}
