package fix

func RegisterAll(r *Registry) {
	registerComposeFixes(r)
	registerSystemFixes(r)
	registerImageFixes(r)
}
