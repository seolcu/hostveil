# compose

YAML editing primitives for Docker Compose files. The fix engine
uses this to read, edit, save, and diff compose files without
round-tripping through `docker compose config`.

## Files

- **`edit.go`**  `File` type, `Open`, `SetField`, `DeleteField`,
  `RemoveFromList`, `Backup`, `Save`, `Diff`. The `File` holds
  the parsed `yaml.Node` AST plus the original bytes, so `Diff`
  can produce a unified diff without re-parsing.
- **`edit_test.go`**  every primitive is tested against a
  fixture compose file.

## API

```go
// Open a compose file. Returns a *File that owns the parsed AST
// and a copy of the original bytes.
func Open(path string) (*File, error)

// Write a backup of the original file next to it (path + ".bak").
func (f *File) Backup() error

// Save the modified AST back to the original path. Idempotent if
// the file has not been modified.
func (f *File) Save() error

// Produce a unified diff between the original and the current AST.
func (f *File) Diff() string

// Set a field. The path is dot-separated (e.g. "services.web.ports").
func (f *File) SetField(service, path string, value interface{}) error

// Delete a field.
func (f *File) DeleteField(service, path string) error

// Remove a value from a list field (e.g. a capability or a
// security_opt entry). value is interface{}, matched via
// fmt.Sprint(value) — every current call site passes a string.
func (f *File) RemoveFromList(service, path string, value interface{}) error

// Return the service names defined in this compose file.
func (f *File) ServiceNames() ([]string, error)
```

## Round-trip safety

`File.Save` writes the AST back through `yaml.Marshal`. The
output is not byte-for-byte identical to the input  comments and
quoting may change  but it is semantically equivalent. The
`Backup` / `Diff` flow is what hostveil uses to present a
"what would change" preview before applying a fix.

## Tests

```bash
go test ./internal/compose/...
```
