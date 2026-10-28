package glyph

// Resolve picks the set to draw with: an explicit flag wins, then the
// environment, then Plain.
//
// Only the flag can fail, for the reason theme.Resolve gives: a user who
// typed --glyphs deserves to be told they typed it wrong, while a stale
// environment variable falls back silently because it was not typed just
// now and is not worth refusing to start over.
func Resolve(flag, env string) (Set, error) {
	if flag != "" {
		s, ok := Lookup(flag)
		if !ok {
			return Plain, &unknownSetError{name: flag}
		}
		return s, nil
	}
	if s, ok := Lookup(env); ok {
		return s, nil
	}
	return Plain, nil
}
