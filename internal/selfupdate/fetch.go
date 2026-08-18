package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strconv"
	"strings"
)

// maxArchive bounds what will be read from the network. The archives are a few
// megabytes; this is the difference between a bad response and filling the
// disk of a host that hostveil is supposed to be looking after.
const maxArchive = 64 << 20

// Client is the HTTP surface this package needs, so a test can answer without
// a network.
type Client interface {
	Do(req *http.Request) (*http.Response, error)
}

// Latest resolves the newest published release by following the redirect
// /releases/latest sends, which is the same thing the install script does and
// the same reason: a draft release is not "Latest", so a release whose
// pipeline failed and was demoted to a draft never reaches anybody.
//
// It deliberately does not use the API. The redirect needs no token, is not
// rate-limited the way api.github.com is for unauthenticated callers, and
// answers the only question being asked.
func Latest(ctx context.Context, c Client) (Release, error) {
	url := "https://github.com/" + Repo + "/releases/latest"
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return Release{}, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return Release{}, ctxErr(ctx, fmt.Errorf("asking GitHub for the latest release: %w", err))
	}
	defer resp.Body.Close()

	// The client is configured not to follow redirects, so the answer is in
	// the header. A 200 here means something in front of GitHub answered
	// instead, and treating its body as a version is how a captive portal
	// becomes an install.
	loc := resp.Header.Get("Location")
	if loc == "" {
		return Release{}, fmt.Errorf("GitHub did not redirect to a release (got %s); "+
			"something may be intercepting the request", resp.Status)
	}
	tag := loc[strings.LastIndex(loc, "/")+1:]
	version := strings.TrimPrefix(tag, "v")
	if !validReleaseVersion(version) {
		return Release{}, fmt.Errorf("could not read a version out of %q", loc)
	}

	asset := fmt.Sprintf("hostveil-%s-%s.tar.gz", runtime.GOOS, runtime.GOARCH)
	base := fmt.Sprintf("https://github.com/%s/releases/download/v%s/", Repo, version)
	return Release{
		Version: version,
		Asset:   asset,
		URL:     base + asset,
		Sums:    base + "hostveil-checksums.txt",
	}, nil
}

// Download fetches the release archive and its checksums file, and returns the
// archive only if the two agree.
//
// The checksum is not advisory. An archive that is not listed, or listed with
// a different hash, is discarded rather than installed with a warning: this
// runs as root, and "the download looked wrong but I went ahead" is not a
// sentence this program gets to say about a binary it is about to become.
func Download(ctx context.Context, c Client, rel Release) ([]byte, error) {
	sums, err := get(ctx, c, rel.Sums)
	if err != nil {
		return nil, fmt.Errorf("downloading the checksums for v%s: %w", rel.Version, err)
	}
	want, err := checksumFor(string(sums), rel.Asset)
	if err != nil {
		return nil, err
	}

	archive, err := get(ctx, c, rel.URL)
	if err != nil {
		return nil, fmt.Errorf("downloading %s: %w", rel.Asset, err)
	}
	sum := sha256.Sum256(archive)
	if got := hex.EncodeToString(sum[:]); got != want {
		return nil, fmt.Errorf("%s does not match the checksum the release publishes "+
			"(got %s, want %s); refusing to install it", rel.Asset, got[:16], want[:16])
	}
	return archive, nil
}

// checksumFor reads one entry out of a sha256sum-format file. The asterisk
// form is what sha256sum writes in binary mode and what goreleaser emits.
func checksumFor(sums, asset string) (string, error) {
	var found string
	for _, line := range strings.Split(sums, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		if name := strings.TrimPrefix(fields[1], "*"); name == asset {
			decoded, err := hex.DecodeString(fields[0])
			if err != nil || len(decoded) != sha256.Size {
				return "", fmt.Errorf("%s has an invalid SHA-256 entry in the checksums file", asset)
			}
			if found != "" {
				return "", fmt.Errorf("%s is listed more than once in the checksums file", asset)
			}
			found = strings.ToLower(fields[0])
		}
	}
	if found != "" {
		return found, nil
	}
	return "", fmt.Errorf("%s is not listed in the release's checksums file, so there is "+
		"nothing to verify it against", asset)
}

func get(ctx context.Context, c Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, ctxErr(ctx, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxArchive+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxArchive {
		return nil, fmt.Errorf("%s returned more than %d bytes", url, maxArchive)
	}
	return b, nil
}

func validReleaseVersion(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		if _, err := strconv.ParseUint(p, 10, 64); err != nil {
			return false
		}
	}
	return true
}
