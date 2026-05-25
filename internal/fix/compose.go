package fix

import (
	"fmt"
	"os/exec"
	"regexp"

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
	del := func(field string) Action {
		return Action{
			Type:     ActionEdit,
			Label:    fmt.Sprintf("Remove %s", field),
			EditPath: field,
			Apply: func(ctx Context) error {
				return composeDel(ctx, field)
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

	r.Register(&Fix{FindingID: "trivy.ds001", Label: "Disable privileged mode", Actions: []Action{edit("privileged", false)}})
	r.Register(&Fix{FindingID: "trivy.ds002", Label: "Enable read-only root filesystem", Actions: []Action{edit("read_only", true)}})
	r.Register(&Fix{FindingID: "trivy.ds003", Label: "Remove pid_mode: host", Warning: "Container loses host PID access.", Actions: []Action{del("pid_mode")}})
	r.Register(&Fix{FindingID: "trivy.ds004", Label: "Remove ipc_mode: host", Warning: "Container loses host IPC access.", Actions: []Action{del("ipc_mode")}})
	r.Register(&Fix{FindingID: "trivy.ds005", Label: "Drop dangerous capabilities", Actions: []Action{drop("cap_add", "SYS_ADMIN"), drop("cap_add", "NET_ADMIN"), drop("cap_add", "SYS_RAWIO"), drop("cap_add", "SYS_PTRACE"), drop("cap_add", "SYS_MODULE")}})
	r.Register(&Fix{FindingID: "trivy.ds006", Label: "Add no-new-privileges", Actions: []Action{edit("security_opt", []interface{}{"no-new-privileges:true"})}})
	r.Register(&Fix{FindingID: "trivy.ds008", Label: "Change restart to unless-stopped", Actions: []Action{edit("restart", "unless-stopped")}})
	r.Register(&Fix{FindingID: "trivy.ds009", Label: "Set non-root user", Warning: "Ensure image supports non-root operation.", Actions: []Action{edit("user", "1000:1000")}})
	r.Register(&Fix{FindingID: "trivy.ds010", Label: "Add memory limit", Actions: []Action{edit("deploy.resources.limits.memory", "512M")}})
	r.Register(&Fix{FindingID: "trivy.ds011", Label: "Add CPU limit", Actions: []Action{edit("deploy.resources.limits.cpus", "1.0")}})
	r.Register(&Fix{FindingID: "trivy.ds012", Label: "Add healthcheck", Warning: "Uses default TCP check; customize if needed.", Actions: []Action{edit("healthcheck", map[string]interface{}{"test": []interface{}{"CMD", "curl", "-f", "http://localhost/"}, "interval": "30s", "timeout": "10s", "retries": 3})}})
	r.Register(&Fix{FindingID: "trivy.ds013", Label: "Add tmpfs with noexec", Actions: []Action{edit("tmpfs", "/tmp:noexec")}})
	r.Register(&Fix{FindingID: "trivy.ds014", Label: "Remove seccomp: unconfined", Actions: []Action{drop("security_opt", "seccomp:unconfined")}})
	r.Register(&Fix{FindingID: "trivy.ds015", Label: "Remove apparmor: unconfined", Actions: []Action{drop("security_opt", "apparmor:unconfined")}})

	// Review (≥2 actions)
	r.Register(&Fix{
		FindingID: "trivy.dr001",
		Label:     "Change network_mode: host",
		Actions: []Action{
			{Type: ActionEdit, Label: "Remove (default to bridge)", Apply: func(ctx Context) error { return composeDel(ctx, "network_mode") }},
			{Type: ActionEdit, Label: "Assign to overlay network", Apply: func(ctx Context) error { return composeEdit(ctx, "network_mode", "overlay") }},
		},
	})
	r.Register(&Fix{
		FindingID: "trivy.dr002",
		Label:     "Restrict host port mapping",
		Actions: []Action{
			{Type: ActionEdit, Label: "Bind to 127.0.0.1 only", Apply: func(ctx Context) error { return composePortRestrict(ctx, "127.0.0.1") }},
			{Type: ActionEdit, Label: "Remove port mapping", Apply: func(ctx Context) error { return composeDel(ctx, "ports") }},
		},
	})
	r.Register(&Fix{
		FindingID: "trivy.dr003",
		Label:     "Secure volume mounts",
		Actions: []Action{
			{Type: ActionEdit, Label: "Add :ro flag", Apply: func(ctx Context) error { return composeVolumeRO(ctx) }},
			{Type: ActionPrompt, Label: "Migrate to named volumes", Description: "Replace host path with a volume name and add to top-level volumes."},
		},
	})
	r.Register(&Fix{
		FindingID: "trivy.dr004",
		Label:     "Remove secrets from env_file",
		Actions: []Action{
			{Type: ActionEdit, Label: "Restrict .env permissions", Apply: func(ctx Context) error { return exec.Command("chmod", "600", ctx.Finding.Metadata["env_path"]).Run() }},
			{Type: ActionPrompt, Label: "Migrate to Docker secrets", Description: "Define secrets in the compose file and reference via secrets:."},
		},
	})
}

var rePortPrefix = regexp.MustCompile(`^\d+:`)

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
		raw, _ := f.GetFieldRaw(svc, "ports")
		if raw != "" {
			fixed := rePortPrefix.ReplaceAllString(raw, bind+":")
			f.SetField(svc, "ports", fixed)
		}
	}
	return f.Save()
}

func composeVolumeRO(ctx Context) error {
	f, err := openComposeFile(ctx)
	if err != nil {
		return err
	}
	vol := ctx.Finding.Evidence["volume"]
	if vol == "" {
		return fmt.Errorf("no volume evidence")
	}
	svcs, err := targetServices(f, ctx.Finding.Service)
	if err != nil {
		return err
	}
	for _, svc := range svcs {
		f.SetField(svc, "volumes", vol+":ro")
	}
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
