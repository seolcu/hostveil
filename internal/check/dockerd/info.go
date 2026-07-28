package dockerd

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// info is the effective daemon state, as the daemon itself reports it.
//
// This is the only trustworthy source for the three default-hardening rules.
// daemon.json says what the operator wrote down, which after an edit without
// a restart is a statement about the future; `docker info` says what the
// process running right now is doing, which is what an attacker meets.
type info struct {
	noNewPrivileges bool
	usernsRemap     bool
	rootless        bool
	liveRestore     bool
	swarmActive     bool

	// opts is the raw SecurityOptions list, kept for evidence so an operator
	// can see the same string the daemon reports.
	opts []string
}

// securityOptions renders the daemon's security options for evidence, sorted
// so a repeat scan produces no delta nobody caused.
func (i info) securityOptions() string {
	if len(i.opts) == 0 {
		return "none reported"
	}
	out := append([]string(nil), i.opts...)
	sort.Strings(out)
	return strings.Join(out, model.EvidenceSeparator)
}

// infoJSON is the narrow view of `docker info` this domain needs. The full
// document is several kilobytes — the runtime table alone carries every OCI
// feature the installed runc supports — and decoding it into a map would
// mean carrying all of that through a scan for five fields.
type infoJSON struct {
	SecurityOptions    []string `json:"SecurityOptions"`
	LiveRestoreEnabled bool     `json:"LiveRestoreEnabled"`
	Swarm              struct {
		LocalNodeState string `json:"LocalNodeState"`
	} `json:"Swarm"`
}

// readInfo asks the daemon what it is actually doing.
//
// The format is `{{json .}}` rather than the shorter `--format json`, which
// only exists in Docker CLI 23 and later. A checker that fails on an older
// CLI reports a degraded domain on a host that is merely not new, and the
// difference costs nothing to avoid.
func readInfo(ctx context.Context, r platform.CommandRunner) (info, bool, string) {
	out, err := r.Run(ctx, "docker", "info", "--format", "{{json .}}")
	if err != nil {
		return info{}, false, "cannot read the daemon's effective configuration with `docker info` — its default hardening settings were not audited"
	}
	var d infoJSON
	if err := json.Unmarshal(out, &d); err != nil {
		return info{}, false, "the daemon's `docker info` output could not be parsed — its default hardening settings were not audited"
	}

	i := info{
		opts:        d.SecurityOptions,
		liveRestore: d.LiveRestoreEnabled,
		swarmActive: d.Swarm.LocalNodeState == "active",
	}
	// SecurityOptions is a list of "name=value" entries where the presence of
	// the name is the signal: the daemon lists a feature only when it is in
	// force, so absence means off rather than unknown.
	for _, o := range d.SecurityOptions {
		switch name, _, _ := strings.Cut(o, ","); name {
		case "name=no-new-privileges":
			i.noNewPrivileges = true
		case "name=userns":
			i.usernsRemap = true
		case "name=rootless":
			i.rootless = true
		}
	}
	return i, true, ""
}
