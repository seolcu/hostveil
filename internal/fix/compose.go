package fix

import (
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"strings"

	"github.com/seolcu/hostveil/internal/compose"
)

func registerComposeFixes(r *Registry) {
	edit := func(field string, value interface{}) Action {
		return Action{
			Type:     ActionEdit,
			Label:    fmt.Sprintf("Set %s: %v", field, value),
			EditPath: field,
			Apply: func(ctx Context) error {
				return composeEdit(ctx, field, value)
			},
		}
	}
	drop := func(field string, value interface{}) Action {
		return Action{
			Type:     ActionEdit,
			Label:    fmt.Sprintf("Remove %v from %s", value, field),
			EditPath: field,
			Apply: func(ctx Context) error {
				return composeDrop(ctx, field, value)
			},
		}
	}

	r.Register(&Fix{FindingID: "compose.ds001", Label: "Disable privileged mode", Actions: []Action{edit("privileged", false)}})
	r.Register(&Fix{FindingID: "compose.ds002", Label: "Enable read-only root filesystem", Actions: []Action{edit("read_only", true)}})
	r.Register(&Fix{FindingID: "compose.ds003", Label: "Remove pid: host", Actions: []Action{{Type: ActionEdit, Label: "Remove pid: host", Warning: "Container loses host PID access.", Apply: func(ctx Context) error { return composeDel(ctx, "pid") }}}})
	r.Register(&Fix{FindingID: "compose.ds004", Label: "Remove ipc: host", Actions: []Action{{Type: ActionEdit, Label: "Remove ipc: host", Warning: "Container loses host IPC access.", Apply: func(ctx Context) error { return composeDel(ctx, "ipc") }}}})
	r.Register(&Fix{FindingID: "compose.ds005", Label: "Drop dangerous capabilities", Actions: []Action{{
		Type:  ActionEdit,
		Label: "Drop all dangerous capabilities",
		Apply: func(ctx Context) error {
			return composeDropBatch(ctx, "cap_add", []interface{}{
				"SYS_ADMIN", "NET_ADMIN", "SYS_RAWIO", "SYS_PTRACE", "SYS_MODULE",
			})
		},
	}}})
	r.Register(&Fix{FindingID: "compose.ds006", Label: "Add no-new-privileges", Actions: []Action{edit("security_opt", []interface{}{"no-new-privileges:true"})}})
	r.Register(&Fix{FindingID: "compose.ds007", Label: "Remove userns_mode: host", Actions: []Action{{Type: ActionEdit, Label: "Remove userns_mode: host", Warning: "Container loses host user namespace access.", Apply: func(ctx Context) error { return composeDel(ctx, "userns_mode") }}}})
	r.Register(&Fix{FindingID: "compose.ds008", Label: "Change restart to unless-stopped", Actions: []Action{edit("restart", "unless-stopped")}})
	r.Register(&Fix{
		FindingID: "compose.ds009",
		Label:     "Set non-root user",
		Actions: []Action{
			{Type: ActionEdit, Label: "Set user: 1000:1000 (common default)", Warning: "Ensure the container image supports running as UID 1000.", Apply: func(ctx Context) error { return composeEdit(ctx, "user", "1000:1000") }},
			{Type: ActionEdit, Label: "Set user: 65534:nobody", Warning: "Ensure the container image supports running as nobody.", Apply: func(ctx Context) error { return composeEdit(ctx, "user", "65534:nobody") }},
		},
	})
	r.Register(&Fix{FindingID: "compose.ds010", Label: "Add memory limit", Actions: []Action{edit("deploy.resources.limits.memory", "512M")}})
	r.Register(&Fix{FindingID: "compose.ds011", Label: "Add CPU limit", Actions: []Action{edit("deploy.resources.limits.cpus", "1.0")}})
	r.Register(&Fix{FindingID: "compose.ds012", Label: "Add healthcheck", Actions: []Action{{Type: ActionEdit, Label: "Add healthcheck with detected port", Apply: func(ctx Context) error {
		port := ctx.Finding.Metadata["container_port"]
		if port == "" {
			port = "80"
		}
		return composeEdit(ctx, "healthcheck", map[string]interface{}{"test": []interface{}{"CMD", "curl", "-f", "http://localhost:" + port + "/"}, "interval": "30s", "timeout": "10s", "retries": 3})
	}}}})
	r.Register(&Fix{FindingID: "compose.ds013", Label: "Add tmpfs with noexec", Actions: []Action{edit("tmpfs", "/tmp:noexec")}})
	r.Register(&Fix{FindingID: "compose.ds014", Label: "Remove seccomp: unconfined", Actions: []Action{drop("security_opt", "seccomp:unconfined")}})
	r.Register(&Fix{FindingID: "compose.ds015", Label: "Remove apparmor: unconfined", Actions: []Action{drop("security_opt", "apparmor:unconfined")}})

	// Review (≥2 actions)
	r.Register(&Fix{
		FindingID: "compose.dr001",
		Label:     "Change network_mode: host",
		Actions: []Action{
			{Type: ActionEdit, Label: "Remove (default to bridge)", Apply: func(ctx Context) error { return composeDel(ctx, "network_mode") }},
			{Type: ActionEdit, Label: "Assign to bridge network", Apply: func(ctx Context) error { return composeEdit(ctx, "network_mode", "bridge") }},
		},
	})
	r.Register(&Fix{
		FindingID: "compose.dr002",
		Label:     "Restrict host port mapping",
		Actions: []Action{
			{Type: ActionEdit, Label: "Bind to 127.0.0.1 only", Apply: func(ctx Context) error { return composePortRestrict(ctx, "127.0.0.1") }},
			{Type: ActionEdit, Label: "Remove port mapping", Apply: func(ctx Context) error { return composeDel(ctx, "ports") }},
		},
	})
	r.Register(&Fix{
		FindingID: "compose.dr003",
		Label:     "Secure volume mounts",
		Actions: []Action{
			{Type: ActionEdit, Label: "Add :ro flag", Apply: func(ctx Context) error { return composeVolumeRO(ctx) }},
		},
	})
	r.Register(&Fix{
		FindingID: "compose.dr004",
		Label:     "Restrict env_file permissions",
		Actions: []Action{
			{Type: ActionEdit, Label: "Restrict .env permissions", Apply: func(ctx Context) error {
				envPath := ctx.Finding.Metadata["env_path"]
				if envPath == "" {
					return fmt.Errorf("env_path not found in finding metadata")
				}
				return exec.Command("chmod", "600", envPath).Run()
			}},
		},
	})
}

// rePortPrefix matches the leading host-side portion of a Compose port mapping,
// which is either `HOST_PORT:` (short form, binds to 0.0.0.0) or
// `BIND_IP:HOST_PORT:` (long form, may bind to 0.0.0.0 or a specific IP).
// Examples that match: "8080:80", "127.0.0.1:8080:80", "0.0.0.0:8080:80".
// Examples that do not match: "80" (container port only, no host binding).
var rePortPrefix = regexp.MustCompile(`^(?:\d+\.?\d*\.?\d*\.?\d*:)?(\d+):`)

// restrictPort replaces the host-side bind portion of a Compose port mapping
// with the given bind address. Returns the new string and true if the input
// was modified.
//
// Recognized forms (all use ":" as separator):
//   - "80"                     — container port only, no host binding, no change
//   - "8080:80"                — short form (binds 0.0.0.0:HOST), prepend bind:
//   - "127.0.0.1:8080:80"      — long form with explicit bind IP, replace IP
//   - "0.0.0.0:8080:80"        — long form with wildcard IP, replace IP
//
// Range syntax (e.g. "3000-3005") and protocol suffixes (e.g. "8080:80/tcp")
// are preserved as-is.
func restrictPort(v, bind string) (string, bool) {
	if v == "" {
		return v, false
	}
	// Split off the optional protocol suffix.
	rest := v
	proto := ""
	if idx := strings.LastIndex(v, "/"); idx > 0 {
		rest = v[:idx]
		proto = v[idx:]
	}
	// If there's no ":", this is a container-port-only mapping.
	// Nothing to restrict on the host side.
	if !strings.Contains(rest, ":") {
		return v, false
	}
	// Count colons to decide between short and long form.
	// Long form (BIND_IP:HOST:CONTAINER) has 2 colons; short (HOST:CONTAINER) has 1.
	// Anything else (range, IPv6) we leave alone.
	firstColon := strings.Index(rest, ":")
	lastColon := strings.LastIndex(rest, ":")
	if firstColon == lastColon {
		// Short form: HOST:CONTAINER
		// e.g. "8080:80" -> "127.0.0.1:8080:80"
		return bind + ":" + rest + proto, true
	}
	// Long form: BIND_IP:HOST:CONTAINER
	// Replace the leading IP portion with `bind`.
	// Find the second colon.
	secondColon := strings.Index(rest[firstColon+1:], ":") + firstColon + 1
	hostPort := rest[firstColon+1 : secondColon]
	containerPort := rest[secondColon+1:]
	if strings.Contains(hostPort, "-") || strings.Contains(containerPort, "-") {
		// Range syntax — leave it alone for now.
		return v, false
	}
	return bind + ":" + hostPort + ":" + containerPort + proto, true
}

func composePortRestrict(ctx Context, bind string) error {
	f, err := openComposeFile(ctx)
	if err != nil {
		return err
	}
	svcs, err := targetServices(f, ctx.Finding.Service)
	if err != nil {
		return err
	}
	for _, svc := range svcs {
		vals, err := f.GetFieldStrings(svc, "ports")
		if err != nil {
			log.Printf("fix: cannot read ports for service %q: %v", svc, err)
			continue
		}
		if len(vals) == 0 {
			continue
		}
		changed := false
		fixed := make([]interface{}, 0, len(vals))
		for _, v := range vals {
			newV, ok := restrictPort(v, bind)
			if ok {
				changed = true
			}
			fixed = append(fixed, newV)
		}
		if !changed {
			log.Printf("fix: no host-bound port found for service %q (already restricted or no host port)", svc)
		}
		if err := f.SetField(svc, "ports", fixed); err != nil {
			return err
		}
	}
	ctx.Diff = f.Diff()
	return f.Save()
}

func composeVolumeRO(ctx Context) error {
	f, err := openComposeFile(ctx)
	if err != nil {
		return err
	}
	svcs, err := targetServices(f, ctx.Finding.Service)
	if err != nil {
		return err
	}
	targetVol := ctx.Finding.Evidence["volume"]
	for _, svc := range svcs {
		vols, err := f.GetFieldStrings(svc, "volumes")
		if err != nil || len(vols) == 0 {
			return fmt.Errorf("no volumes found for service %q", svc)
		}
		fixed := make([]interface{}, len(vols))
		for i, v := range vols {
			if strings.Contains(v, ":ro") {
				fixed[i] = v
			} else if targetVol == "" || strings.HasPrefix(v, strings.Split(targetVol, ":")[0]) {
				fixed[i] = v + ":ro"
			} else {
				fixed[i] = v
			}
		}
		if err := f.SetField(svc, "volumes", fixed); err != nil {
			return fmt.Errorf("failed to set read-only volumes: %w", err)
		}
	}
	ctx.Diff = f.Diff()
	return f.Save()
}

func composeEdit(ctx Context, field string, value interface{}) error {
	f, err := openComposeFile(ctx)
	if err != nil {
		return err
	}
	svcs, err := targetServices(f, ctx.Finding.Service)
	if err != nil {
		return err
	}
	for _, svc := range svcs {
		if err := f.SetField(svc, field, value); err != nil {
			return err
		}
	}
	ctx.Diff = f.Diff()
	return f.Save()
}

func composeDel(ctx Context, field string) error {
	f, err := openComposeFile(ctx)
	if err != nil {
		return err
	}
	svcs, err := targetServices(f, ctx.Finding.Service)
	if err != nil {
		return err
	}
	for _, svc := range svcs {
		if err := f.DeleteField(svc, field); err != nil {
			return err
		}
	}
	ctx.Diff = f.Diff()
	return f.Save()
}

func composeDrop(ctx Context, field string, value interface{}) error {
	f, err := openComposeFile(ctx)
	if err != nil {
		return err
	}
	svcs, err := targetServices(f, ctx.Finding.Service)
	if err != nil {
		return err
	}
	for _, svc := range svcs {
		if err := f.RemoveFromList(svc, field, value); err != nil {
			return err
		}
	}
	ctx.Diff = f.Diff()
	return f.Save()
}

func composeDropBatch(ctx Context, field string, values []interface{}) error {
	f, err := openComposeFile(ctx)
	if err != nil {
		return err
	}
	svcs, err := targetServices(f, ctx.Finding.Service)
	if err != nil {
		return err
	}
	for _, svc := range svcs {
		for _, v := range values {
			if err := f.RemoveFromList(svc, field, v); err != nil {
				return err
			}
		}
	}
	ctx.Diff = f.Diff()
	return f.Save()
}

func openComposeFile(ctx Context) (*compose.File, error) {
	path := ctx.ComposePath()
	if path == "" {
		return nil, fmt.Errorf("no compose path in finding")
	}
	f, err := compose.Open(path)
	if err != nil {
		return nil, err
	}
	if err := f.Backup(); err != nil {
		return nil, err
	}
	return f, nil
}

func targetServices(f *compose.File, service string) ([]string, error) {
	if service != "" {
		return []string{service}, nil
	}
	return f.ServiceNames()
}
