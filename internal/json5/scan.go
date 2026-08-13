package json5

import (
	"fmt"
)

// span is the byte extent of a value in the original source, end-exclusive.
type span struct{ start, end int }

// locate walks the document and records where each addressable value sits.
//
// It is a locator, not a parser: the decoded values come from Decode, and
// this pass exists only to answer "which bytes are the value at
// gateway.controlUi.allowInsecureAuth" so an edit can replace exactly those
// and leave every comment, blank line and trailing comma alone.
//
// Paths are dotted and built the same way internal/check/agent's lookup walks
// them, so a path that produced a finding is a path this can address. A key
// containing a literal '.' makes its own path ambiguous — two different keys
// can spell the same dotted path — and every such path is reported so Set
// refuses it rather than editing whichever one it happened to record last.
func locate(src []byte) (map[string]span, map[string]bool, error) {
	s := &scanner{src: src, spans: map[string]span{}, amb: map[string]bool{}}
	s.ws()
	if err := s.value(""); err != nil {
		return nil, nil, err
	}
	s.ws()
	if s.i != len(s.src) {
		return nil, nil, fmt.Errorf("unexpected content after the top-level value at byte %d", s.i)
	}
	return s.spans, s.amb, nil
}

type scanner struct {
	src   []byte
	i     int
	spans map[string]span
	amb   map[string]bool
}

// ws advances past whitespace and both comment forms. Comments are ordinary
// whitespace to a locator; keeping them is the caller's whole purpose, so
// they are stepped over and never recorded.
func (s *scanner) ws() {
	for s.i < len(s.src) {
		switch c := s.src[s.i]; {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			s.i++
		case c == '/' && s.i+1 < len(s.src) && s.src[s.i+1] == '/':
			for s.i < len(s.src) && s.src[s.i] != '\n' {
				s.i++
			}
		case c == '/' && s.i+1 < len(s.src) && s.src[s.i+1] == '*':
			s.i += 2
			for s.i+1 < len(s.src) && (s.src[s.i] != '*' || s.src[s.i+1] != '/') {
				s.i++
			}
			s.i = min(s.i+2, len(s.src))
		default:
			return
		}
	}
}

func (s *scanner) value(path string) error {
	s.ws()
	if s.i >= len(s.src) {
		return fmt.Errorf("unexpected end of config where a value was expected")
	}
	start := s.i
	var err error
	switch s.src[s.i] {
	case '{':
		err = s.object(path)
	case '[':
		err = s.array()
	case '"', '\'':
		err = s.str()
	default:
		err = s.bare()
	}
	if err != nil {
		return err
	}
	if path != "" {
		if _, seen := s.spans[path]; seen {
			s.amb[path] = true
		}
		s.spans[path] = span{start, s.i}
	}
	return nil
}

func (s *scanner) object(path string) error {
	s.i++ // '{'
	for {
		s.ws()
		if s.i >= len(s.src) {
			return fmt.Errorf("unterminated object at byte %d", s.i)
		}
		if s.src[s.i] == '}' {
			s.i++
			return nil
		}
		key, err := s.key()
		if err != nil {
			return err
		}
		s.ws()
		if s.i >= len(s.src) || s.src[s.i] != ':' {
			return fmt.Errorf("expected ':' after key %q at byte %d", key, s.i)
		}
		s.i++
		child := key
		if path != "" {
			child = path + "." + key
		}
		if err := s.value(child); err != nil {
			return err
		}
		s.ws()
		if s.i >= len(s.src) {
			return fmt.Errorf("unterminated object at byte %d", s.i)
		}
		switch s.src[s.i] {
		case ',':
			s.i++
		case '}':
			s.i++
			return nil
		default:
			return fmt.Errorf("expected ',' or '}' after the value of %q at byte %d", key, s.i)
		}
	}
}

func (s *scanner) array() error {
	s.i++ // '['
	for {
		s.ws()
		if s.i >= len(s.src) {
			return fmt.Errorf("unterminated array at byte %d", s.i)
		}
		if s.src[s.i] == ']' {
			s.i++
			return nil
		}
		// Elements get no path: a dotted path cannot address an array
		// element, and lookup in the agent checker cannot either.
		if err := s.value(""); err != nil {
			return err
		}
		s.ws()
		if s.i >= len(s.src) {
			return fmt.Errorf("unterminated array at byte %d", s.i)
		}
		switch s.src[s.i] {
		case ',':
			s.i++
		case ']':
			s.i++
			return nil
		default:
			return fmt.Errorf("expected ',' or ']' in array at byte %d", s.i)
		}
	}
}

// key reads an object key, quoted or bare. JSON5 permits both, and a real
// OpenClaw config uses both.
func (s *scanner) key() (string, error) {
	s.ws()
	if s.i >= len(s.src) {
		return "", fmt.Errorf("unexpected end of config where a key was expected")
	}
	if c := s.src[s.i]; c == '"' || c == '\'' {
		start := s.i
		if err := s.str(); err != nil {
			return "", err
		}
		// Strip the quotes. Escapes are left as written: these keys are
		// identifiers, and a key needing an escape is one this cannot
		// address anyway — it would not match the dotted path a finding
		// carries either.
		return string(s.src[start+1 : s.i-1]), nil
	}
	start := s.i
	for s.i < len(s.src) && isBareKeyByte(s.src[s.i]) {
		s.i++
	}
	if s.i == start {
		return "", fmt.Errorf("expected a key at byte %d", s.i)
	}
	return string(s.src[start:s.i]), nil
}

func isBareKeyByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c == '_' || c == '$' || c == '-':
		return true
	default:
		return false
	}
}

// str consumes a quoted string, honouring backslash escapes so a quote
// inside a value never ends it early.
func (s *scanner) str() error {
	quote := s.src[s.i]
	s.i++
	for s.i < len(s.src) {
		switch s.src[s.i] {
		case '\\':
			s.i += 2
			continue
		case quote:
			s.i++
			return nil
		}
		s.i++
	}
	return fmt.Errorf("unterminated string starting at byte %d", s.i)
}

// bare consumes a number, true, false or null — anything running up to the
// next structural byte, whitespace or comment.
func (s *scanner) bare() error {
	start := s.i
	for s.i < len(s.src) {
		c := s.src[s.i]
		if c == ',' || c == '}' || c == ']' || c == ':' ||
			c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			break
		}
		if c == '/' && s.i+1 < len(s.src) && (s.src[s.i+1] == '/' || s.src[s.i+1] == '*') {
			break
		}
		s.i++
	}
	if s.i == start {
		return fmt.Errorf("expected a value at byte %d", s.i)
	}
	return nil
}
