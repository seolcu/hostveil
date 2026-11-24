package core

import (
	"strconv"
	"strings"

	"github.com/seolcu/hostveil/internal/model"
)

// publishFixes are the compose findings whose fix rebinds a published port to
// 127.0.0.1, which closes the port on every other interface.
var publishFixes = map[string]bool{
	"compose.ds018": true, // datastore
	"compose.ds019": true, // admin panel
	"compose.dr002": true, // any other published port
}

// linkConsequences sets ResolvedBy on the findings that report, from another
// domain, a port a compose file publishes on every interface.
//
// One published port shows up three times: compose says the file publishes
// it (compose.ds018, with a fix that binds it to 127.0.0.1), the ports domain
// sees docker-proxy listening on it (ports.exposed-datastore, Manual, since
// there is no listener config to edit), and with ufw on, the firewall domain
// sees it bypass ufw (firewall.docker-bypass). The compose fix and a recreate
// remove all three, and a rescan shows it. Without the link, the
// projection beside the score left the other two standing, so it promised
// less than "fix all safe" delivered.
//
// The link is by host port and only to docker-proxy listeners and Docker's
// published ports: a native service on the same port is not something a
// compose file can close.
func linkConsequences(findings []model.Finding) {
	byPort := map[string]string{}
	for _, f := range findings {
		if publishFixes[f.ID] && f.Active() {
			if p := f.Evidence["port"]; p != "" {
				byPort[p] = f.Key()
			}
		}
	}
	if len(byPort) == 0 {
		return
	}
	for i := range findings {
		f := &findings[i]
		switch {
		case (f.ID == "ports.exposed-datastore" || f.ID == "ports.exposed-admin") && f.Evidence["process"] == "docker-proxy":
			if k, ok := byPort[f.Evidence["port"]]; ok {
				f.ResolvedBy = []string{k}
			}
		case f.ID == "ports.exposed":
			f.ResolvedBy = coveredPorts(f.Evidence["ports"], byPort, "docker-proxy")
		case f.ID == "firewall.docker-bypass":
			f.ResolvedBy = coveredPorts(f.Evidence["published"], byPort, "")
		}
	}
}

// coveredPorts reads a list written "5432 (owner), 6379 (owner)" and returns
// the compose findings that cover every port in it, or nil when any port is
// not covered (or, with owner set, is held by anything else), because then
// the finding outlives the compose fixes.
func coveredPorts(list string, byPort map[string]string, owner string) []string {
	var keys []string
	seen := map[string]bool{}
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		port, who, _ := strings.Cut(item, " ")
		if _, err := strconv.Atoi(port); err != nil {
			return nil
		}
		if owner != "" && strings.Trim(who, "()") != owner {
			return nil
		}
		k, ok := byPort[port]
		if !ok {
			return nil
		}
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	return keys
}
