package fix

// registerAgent wires the agent-runtime permission fixes into the registry.
//
// Only the two mode findings are registered. Everything else the agent domain
// reports is a config-key edit, and those are declined for reasons recorded
// in Default's doc comment.
//
// Exact IDs, not an "agent.*" glob, for the same reason registerFilePerms
// spells its five out: TestEveryRegisteredFixIsValid rejects globs so that
// widening what the registry claims to fix is a deliberate act.
func registerAgent(r *Registry) {
	for _, id := range []string{
		"agent.config-perms",
		"agent.secret-exposed",
	} {
		r.Register(id, buildTightenMode)
	}
}
