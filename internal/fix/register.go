package fix

// Default returns a Registry with every built-in fix registered. The
// engine treats this registry as the authority for which findings are
// Auto/Review; anything without a registered fix is Manual.
func Default() *Registry {
	r := NewRegistry()
	registerCompose(r)
	registerSSH(r)
	registerUpdates(r)
	return r
}
