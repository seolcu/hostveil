package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/check/checktest"
)

// The question every one of these is about: may hostveil touch this file, and
// with which tool. Getting it wrong does not produce an error, it produces a
// package database describing a file that is no longer there, and the next
// `apt upgrade` either reverts the update or refuses to proceed. Neither
// points back at hostveil.
func TestTheOriginDecidesWhichToolActs(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  *checktest.Runner
		path string
		want Origin
	}{
		{
			name: "dpkg owns it",
			run:  checktest.New().Also("dpkg").Script("hostveil: /usr/bin/hostveil\n", "dpkg", "-S", "/usr/bin/hostveil"),
			path: "/usr/bin/hostveil",
			want: OriginDeb,
		},
		{
			name: "rpm owns it",
			run:  checktest.New().Also("rpm").Script("hostveil-3.17.0-1.x86_64\n", "rpm", "-qf", "/usr/bin/hostveil"),
			path: "/usr/bin/hostveil",
			want: OriginRPM,
		},
		{
			// The install script's destination, with no package manager
			// claiming it.
			name: "the install script put it there",
			run:  checktest.New().Without("dpkg", "rpm"),
			path: "/usr/bin/hostveil",
			want: OriginStandalone,
		},
		{
			// A copy somebody dropped somewhere. hostveil does not know what
			// it is and must not delete it.
			name: "a copy somewhere else",
			run:  checktest.New().Without("dpkg", "rpm"),
			path: "/opt/tools/hostveil",
			want: OriginUnknown,
		},
		{
			name: "no path at all",
			run:  checktest.New().Without("dpkg", "rpm"),
			path: "",
			want: OriginUnknown,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := DetectOrigin(context.Background(), tc.run, tc.path); got != tc.want {
				t.Errorf("DetectOrigin(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

// A package manager's claim beats the location. A host that has done something
// unusual can have a packaged binary inside GOBIN, and rebuilding it from
// source would leave dpkg describing a file the Go toolchain overwrote.
func TestAPackageClaimBeatsTheLocation(t *testing.T) {
	t.Setenv("GOBIN", "/usr/bin")
	run := checktest.New().Also("dpkg").Script("hostveil: /usr/bin/hostveil\n", "dpkg", "-S", "/usr/bin/hostveil")
	if got := DetectOrigin(context.Background(), run, "/usr/bin/hostveil"); got != OriginDeb {
		t.Errorf("DetectOrigin = %v, want the package answer", got)
	}
}

// go install's destination is recognised so hostveil rebuilds it rather than
// dropping a published binary over somebody's own build.
func TestAGoInstallBinaryIsRecognised(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GOBIN", dir)
	got := DetectOrigin(context.Background(), checktest.New().Without("dpkg", "rpm"), filepath.Join(dir, "hostveil"))
	if got != OriginGoInstall {
		t.Errorf("DetectOrigin = %v, want OriginGoInstall", got)
	}
}

// stubClient answers canned bodies, so the verification logic can be driven
// without a network.
type stubClient struct {
	head string            // Location header for the HEAD request
	body map[string]string // url -> body
	code int
}

func (c stubClient) Do(req *http.Request) (*http.Response, error) {
	status := c.code
	if status == 0 {
		status = http.StatusOK
	}
	if req.Method == http.MethodHead {
		return &http.Response{
			StatusCode: http.StatusFound,
			Header:     http.Header{"Location": []string{c.head}},
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	}
	body, ok := c.body[req.URL.String()]
	if !ok {
		return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader(""))}, nil
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body))}, nil
}

func TestLatestReadsTheVersionOutOfTheRedirect(t *testing.T) {
	c := stubClient{head: "https://github.com/seolcu/hostveil/releases/tag/v3.17.0"}
	rel, err := Latest(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if rel.Version != "3.17.0" {
		t.Errorf("Version = %q, want 3.17.0", rel.Version)
	}
	if !strings.HasSuffix(rel.Sums, "/v3.17.0/hostveil-checksums.txt") {
		t.Errorf("Sums = %q", rel.Sums)
	}
}

// A 200 where a redirect belongs means something answered instead of GitHub,
// and treating its body as a version is how a captive portal becomes an
// install.
func TestLatestRefusesAnAnswerThatIsNotARedirect(t *testing.T) {
	c := stubClient{head: ""}
	if _, err := Latest(context.Background(), c); err == nil {
		t.Fatal("a response with no Location was accepted as a release")
	}
}

// The checksum is the gate, not a warning. This is the whole safety argument
// for a program that is about to replace itself as root.
func TestDownloadRefusesAnArchiveThatDoesNotMatch(t *testing.T) {
	rel := Release{
		Version: "3.17.0", Asset: "a.tar.gz",
		URL:  "https://x/a.tar.gz",
		Sums: "https://x/sums.txt",
	}
	good := "the real archive"
	sum := sha256.Sum256([]byte(good))

	t.Run("matching", func(t *testing.T) {
		c := stubClient{body: map[string]string{
			rel.Sums: hex.EncodeToString(sum[:]) + "  a.tar.gz\n",
			rel.URL:  good,
		}}
		got, err := Download(context.Background(), c, rel)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != good {
			t.Error("the verified archive is not what was served")
		}
	})

	t.Run("swapped", func(t *testing.T) {
		c := stubClient{body: map[string]string{
			rel.Sums: hex.EncodeToString(sum[:]) + "  a.tar.gz\n",
			rel.URL:  "something else entirely",
		}}
		if _, err := Download(context.Background(), c, rel); err == nil {
			t.Fatal("an archive that does not match its checksum was accepted")
		}
	})

	t.Run("not listed", func(t *testing.T) {
		c := stubClient{body: map[string]string{
			rel.Sums: hex.EncodeToString(sum[:]) + "  something-else.tar.gz\n",
			rel.URL:  good,
		}}
		_, err := Download(context.Background(), c, rel)
		if err == nil || !strings.Contains(err.Error(), "not listed") {
			t.Fatalf("an unlisted asset was accepted: %v", err)
		}
	})
}

// gh missing is a note; gh saying no is a refusal. The asymmetry is the point:
// "I could not check" and "I checked and it does not hold" are different
// answers and only one of them is a reason to stop.
func TestProvenanceFailureStopsAndAbsenceDoesNot(t *testing.T) {
	ctx := context.Background()

	checked, err := Provenance(ctx, checktest.New().Without("gh"), "/tmp/x.tar.gz")
	if checked || err != nil {
		t.Errorf("with no gh installed: checked=%v err=%v, want false and no error", checked, err)
	}

	failing := checktest.New().Also("gh").
		Fail(os.ErrPermission, "gh", "attestation", "verify", "/tmp/x.tar.gz", "--repo", Repo)
	checked, err = Provenance(ctx, failing, "/tmp/x.tar.gz")
	if !checked || err == nil {
		t.Errorf("with gh refusing: checked=%v err=%v, want true and an error", checked, err)
	}
}

// Replacing preserves the mode of the file being replaced, so a deployment
// that tightened it keeps its choice.
func TestReplaceIsAtomicAndKeepsTheMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hostveil")
	if err := os.WriteFile(path, []byte("old"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := Replace(path, []byte("new")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "new" {
		t.Fatalf("contents = %q, %v", got, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o750 {
		t.Errorf("mode = %v, want the mode the old file had", info.Mode().Perm())
	}
	// Nothing left behind in the directory it staged through.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("%d files left in the directory, want just the binary", len(entries))
	}
}

// The package asset names are the ones the release actually publishes. Getting
// this wrong means a 404 that reads like a network problem.
func TestPackageAssetNamesMatchTheRelease(t *testing.T) {
	deb, err := PackageAsset(OriginDeb, "3.17.0")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(deb, "hostveil_3.17.0_linux_") || !strings.HasSuffix(deb, ".deb") {
		t.Errorf("deb asset = %q", deb)
	}
	if _, err := PackageAsset(OriginStandalone, "3.17.0"); err == nil {
		t.Error("a non-package origin produced a package asset name")
	}
}

// Uninstalling must not offer to delete the checkpoints as part of the same
// action, and must say where they are.
func TestTheStateNoteNamesTheDirectoryWithoutRemovingIt(t *testing.T) {
	dir := t.TempDir()
	note := StateNote(dir)
	if !strings.Contains(note, dir) {
		t.Errorf("the note does not name the state directory: %q", note)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Error("StateNote removed the directory it was asked about")
	}
	if StateNote(filepath.Join(dir, "gone")) != "" {
		t.Error("a directory that does not exist produced a note about it")
	}
}

// The two sides of this comparison genuinely disagree about the leading v, and
// getting it wrong is silent: `hostveil update` on a current host announces an
// update and reinstalls the version it is already running.
//
// goreleaser stamps `-X main.version=v{{.Version}}`, so a released binary says
// "v3.17.0". Latest trims the tag to "3.17.0" because that is what builds an
// asset URL.
func TestVersionsCompareAcrossTheLeadingV(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"v3.17.0", "3.17.0", true}, // the case that shipped wrong
		{"3.17.0", "v3.17.0", true},
		{"v3.17.0", "v3.17.0", true},
		{"3.17.0", "3.17.0", true},
		{"v3.17.0", "3.18.0", false},
		{"v3-dev", "3.17.0", false}, // a development build is never current
		{"", "3.17.0", false},
		{"", "", false},
	} {
		if got := SameVersion(tc.a, tc.b); got != tc.want {
			t.Errorf("SameVersion(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}
