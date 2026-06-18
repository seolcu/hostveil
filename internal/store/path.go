// Package store contains the SQLite-backed state of hostveil: the
// scan history, finding fingerprints, fix records, suppression list,
// CVE cache, and the session/AI audit logs.
package store

import (
	"os"
	"path/filepath"

	"github.com/seolcu/hostveil/internal/version"
)

// Path layout under the XDG data home.
type Paths struct {
	DataDir   string // ~/.local/share/hostveil/
	StateDB   string // DataDir + "state.db"
	Reports   string // DataDir + "reports/"
	Backups   string // DataDir + "backups/"
	Logs      string // DataDir + "logs/"
	ConfigDir string // ~/.config/hostveil/
}

// Resolve returns the canonical XDG paths for the current user.
// $XDG_DATA_HOME and $XDG_CONFIG_HOME override the defaults.
func Resolve() (*Paths, error) {
	dataHome := os.Getenv("XDG_DATA_HOME")
	if dataHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		dataHome = filepath.Join(home, ".local", "share")
	}
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		configHome = filepath.Join(home, ".config")
	}
		dataDir := filepath.Join(dataHome, version.Name)
	p := &Paths{
		DataDir:   dataDir,
		StateDB:   filepath.Join(dataDir, "state.db"),
		Reports:   filepath.Join(dataDir, "reports"),
		Backups:   filepath.Join(dataDir, "backups"),
		Logs:      filepath.Join(dataDir, "logs"),
		ConfigDir: filepath.Join(configHome, version.Name),
	}
	return p, nil
}

// EnsureDirs creates the on-disk directories the program owns. Safe to
// call on every invocation: the user's home is always writable by the
// user, and the program never invokes the elevation helper for this.
func (p *Paths) EnsureDirs() error {
	for _, d := range []string{p.DataDir, p.Reports, p.Backups, p.Logs, p.ConfigDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	return nil
}
