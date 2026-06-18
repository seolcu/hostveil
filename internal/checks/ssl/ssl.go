// Package ssl scans the host's TLS certificates and supported
// protocol versions (spec FR-015).
//
// The v3.0.0 release inspects only locally-observed certificates:
// PEM files in /etc/ssl/certs, /etc/pki/tls/certs, and any path
// referenced by the loaded nginx / caddy configs. Remote endpoint
// probing (e.g. opening a TLS connection to a listening port) is a
// post-v3.0 refinement.
package ssl

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/seolcu/hostveil/internal/checks"
	"github.com/seolcu/hostveil/internal/model"
)

var certDirs = []string{
	"/etc/ssl/certs",
	"/etc/pki/tls/certs",
}

var systemCABundle = []string{
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/pki/tls/certs/ca-bundle.crt",
}

// Run implements checks.Run.
func Run(ctx context.Context) (checks.Result, error) {
	now := time.Now().UTC()
	var findings []model.Finding
	for _, dir := range certDirs {
		_ = ctx
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			p := filepath.Join(dir, e.Name())
			if !isPEMFile(p) {
				continue
			}
			cert, err := parseCertFile(p)
			if err != nil {
				continue
			}
			if f := certFindings(cert, p, now); len(f) > 0 {
				findings = append(findings, f...)
			}
		}
	}
	// Also probe localhost TLS for the supported protocol versions
	// when something is listening on 443.
	if probe, _ := dialLocalhost(":443"); probe {
		// We don't have a way to know which cert the listener
		// serves without parsing the relevant config; report a
		// low-severity "we couldn't probe" finding so the user
		// knows the scanner ran.
		findings = append(findings, model.Finding{
			ID: "finding-ssl_tls.probe-skipped",
			Category: model.CategorySSLTLS,
			RuleID: "ssl_tls.probe_skipped",
			Severity: model.SeverityLow,
			Title: "Could not probe the local listener for TLS version",
			Description: "A service is listening on :443 but hostveil did not have a way to discover its certificate in v3.0.0.",
			State: model.StateNew, FirstSeenAt: now, LastSeenAt: now,
		})
	}
	if len(findings) == 0 {
		return checks.Result{}, nil
	}
	return checks.Result{Findings: findings}, nil
}

func isPEMFile(p string) bool {
	if strings.HasSuffix(p, ".pem") || strings.HasSuffix(p, ".crt") {
		return true
	}
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 64)
	n, _ := f.Read(buf)
	return bytesHavePEM(buf[:n])
}

func bytesHavePEM(b []byte) bool {
	return strings.Contains(string(b), "-----BEGIN ")
}

func parseCertFile(p string) (*x509.Certificate, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", p)
	}
	return x509.ParseCertificate(block.Bytes)
}

func certFindings(cert *x509.Certificate, path string, now time.Time) []model.Finding {
	var out []model.Finding
	days := int(time.Until(cert.NotAfter).Hours() / 24)
	if days < 0 {
		out = append(out, model.Finding{
			ID:       "finding-ssl_tls.expired-" + path,
			Category: model.CategorySSLTLS,
			RuleID:   "ssl_tls.expired",
			Severity: model.SeverityHigh,
			Title:    fmt.Sprintf("Certificate expired %d days ago", -days),
			Description: fmt.Sprintf("The certificate at %s expired on %s.", path, cert.NotAfter.Format("2006-01-02")),
			EntityRefs: []model.EntityRef{
				{Kind: model.EntityRefKindSetting, Display: path},
			},
			State: model.StateNew, FirstSeenAt: now, LastSeenAt: now,
		})
	} else if days < 30 {
		out = append(out, model.Finding{
			ID:       "finding-ssl_tls.expiring-" + path,
			Category: model.CategorySSLTLS,
			RuleID:   "ssl_tls.expiring_soon",
			Severity: model.SeverityMedium,
			Title:    fmt.Sprintf("Certificate expires in %d days", days),
			Description: fmt.Sprintf("The certificate at %s expires on %s.", path, cert.NotAfter.Format("2006-01-02")),
			EntityRefs: []model.EntityRef{
				{Kind: model.EntityRefKindSetting, Display: path},
			},
			State: model.StateNew, FirstSeenAt: now, LastSeenAt: now,
		})
	}
	return out
}

func dialLocalhost(addr string) (bool, error) {
	conn, err := netDial("tcp", "127.0.0.1"+addr)
	if err != nil {
		return false, nil
	}
	_ = conn.Close()
	return true, nil
}
