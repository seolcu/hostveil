package core

import (
	"context"
	"slices"
	"strings"

	"github.com/seolcu/hostveil/internal/model"
)

// Activation is what Engine.Activate would run: the fixes still waiting on a
// recreate, and the commands that put them in force.
type Activation struct {
	// Fixes counts the applied fixes these commands put in force.
	Fixes int `json:"fixes"`
	// Services names each service the commands recreate, as project/service.
	Services []string `json:"services"`
	// Commands are the merged commands, one per compose project.
	Commands [][]string `json:"commands"`
}

// ActivateOutcome reports a run of Engine.Activate.
type ActivateOutcome struct {
	Activation
	// InForce counts the fixes now in force.
	InForce int `json:"in_force"`
	// Failed maps a command, joined with spaces, to its error.
	Failed   map[string]string    `json:"failed,omitempty"`
	NewScore model.ScoreBreakdown `json:"new_score"`
}

// PendingActivation reports what Activate would run now. An empty result
// means no applied fix is waiting on a recreate.
func (e *Engine) PendingActivation() Activation {
	plan, _ := e.state.activationPlan()
	return plan
}

// Activate recreates the services that applied fixes are waiting on, once
// per compose project, and marks the fixes whose command succeeded as in
// force.
//
// It is a separate step from applying because it is the disruptive half: a
// recreate restarts the service. Applying stays a file edit with a
// checkpoint, and the operator decides when the restart happens. A batch
// that edited one service five times recreates it once: the commands are
// merged here, and no fix runs its own.
func (e *Engine) Activate(ctx context.Context) ActivateOutcome {
	e.applyMu.Lock()
	defer e.applyMu.Unlock()

	plan, byCommand := e.state.activationPlan()
	out := ActivateOutcome{Activation: plan, Failed: map[string]string{}}
	var done []string
	for i, argv := range plan.Commands {
		if err := runEach(ctx, e.runner, [][]string{argv}); err != nil {
			out.Failed[strings.Join(argv, " ")] = err.Error()
			continue
		}
		done = append(done, byCommand[i]...)
	}
	out.InForce = e.state.markInForce(done)
	out.NewScore = e.state.rescore()
	return out
}

// mergeActivations groups `docker compose ... up -d <service>` commands that
// differ only in the service into one command naming every service, in
// first-seen order. Any other command is kept as it is.
func mergeActivations(cmds [][]string, keys []string) (merged [][]string, byCommand [][]string, services []string) {
	index := map[string]int{}
	for i, argv := range cmds {
		prefix, svc, ok := composeUp(argv)
		if !ok {
			merged = append(merged, slices.Clone(argv))
			byCommand = append(byCommand, []string{keys[i]})
			continue
		}
		project := projectOf(prefix)
		if !slices.Contains(services, project+"/"+svc) {
			services = append(services, project+"/"+svc)
		}
		k := strings.Join(prefix, "\x00")
		if j, seen := index[k]; seen {
			if !slices.Contains(merged[j][len(prefix):], svc) {
				merged[j] = append(merged[j], svc)
			}
			if !slices.Contains(byCommand[j], keys[i]) {
				byCommand[j] = append(byCommand[j], keys[i])
			}
			continue
		}
		index[k] = len(merged)
		merged = append(merged, append(slices.Clone(prefix), svc))
		byCommand = append(byCommand, []string{keys[i]})
	}
	return merged, byCommand, services
}

// composeUp splits `docker compose [-f F]... up -d SERVICE` into its prefix
// and the service.
func composeUp(argv []string) (prefix []string, service string, ok bool) {
	n := len(argv)
	if n < 5 || argv[0] != "docker" || argv[1] != "compose" || argv[n-3] != "up" || argv[n-2] != "-d" {
		return nil, "", false
	}
	return argv[:n-1], argv[n-1], true
}

// projectOf names a compose project by the directory of its first file, which
// is how docker compose names it.
func projectOf(prefix []string) string {
	for i := 0; i+1 < len(prefix); i++ {
		if prefix[i] == "-f" {
			dir := prefix[i+1]
			if j := strings.LastIndex(dir, "/"); j >= 0 {
				dir = dir[:j]
			}
			if j := strings.LastIndex(dir, "/"); j >= 0 {
				dir = dir[j+1:]
			}
			return dir
		}
	}
	return "compose"
}
