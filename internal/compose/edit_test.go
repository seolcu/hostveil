package compose

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testCompose = `services:
  web:
    image: nginx:latest
    privileged: true
    ports:
      - "80:80"
    cap_add:
      - SYS_ADMIN
    environment:
      - FOO=bar

  db:
    image: postgres:15
    restart: always
`

func writeTestCompose(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustOpen(t *testing.T, path string) *File {
	t.Helper()
	f, err := Open(path)
	if err != nil {
		t.Fatalf("Open(%q): %v", path, err)
	}
	return f
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestOpen(t *testing.T) {
	path := writeTestCompose(t, testCompose)
	f := mustOpen(t, path)
	if f == nil {
		t.Fatal("Open returned nil")
	}
}

func TestOpen_InvalidYAML(t *testing.T) {
	path := writeTestCompose(t, "invalid: [yaml: broken\n  indentation")
	_, err := Open(path)
	if err == nil {
		t.Error("Open of invalid YAML should return error")
	}
}

func TestOpen_MissingFile(t *testing.T) {
	_, err := Open("/nonexistent/compose.yml")
	if err == nil {
		t.Error("Open of missing file should return error")
	}
}

func TestSetField_Scalar(t *testing.T) {
	path := writeTestCompose(t, testCompose)
	f := mustOpen(t, path)
	if err := f.SetField("web", "privileged", false); err != nil {
		t.Fatalf("SetField: %v", err)
	}
	if err := f.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	out := readFile(t, f.path)
	if !strings.Contains(out, "privileged: false") {
		t.Errorf("output should contain 'privileged: false'\n%s", out)
	}
}

func TestSetField_NewField(t *testing.T) {
	path := writeTestCompose(t, testCompose)
	f := mustOpen(t, path)
	if err := f.SetField("web", "read_only", true); err != nil {
		t.Fatalf("SetField: %v", err)
	}
	f.Save()
	out := readFile(t, f.path)
	if !strings.Contains(out, "read_only: true") {
		t.Errorf("output should contain 'read_only: true'\n%s", out)
	}
}

func TestSetField_NestedPath(t *testing.T) {
	path := writeTestCompose(t, testCompose)
	f := mustOpen(t, path)
	if err := f.SetField("web", "deploy.resources.limits.memory", "512M"); err != nil {
		t.Fatalf("SetField nested: %v", err)
	}
	f.Save()
	out := readFile(t, f.path)
	if !strings.Contains(out, "memory: 512M") {
		t.Errorf("output should contain 'memory: 512M'\n%s", out)
	}
}

func TestSetField_MapValue(t *testing.T) {
	path := writeTestCompose(t, testCompose)
	f := mustOpen(t, path)
	hc := map[string]interface{}{
		"test":     []interface{}{"CMD", "curl", "-f", "/"},
		"interval": "30s",
	}
	if err := f.SetField("web", "healthcheck", hc); err != nil {
		t.Fatalf("SetField healthcheck: %v", err)
	}
	f.Save()
	out := readFile(t, f.path)
	checks := []string{"healthcheck", "interval: 30s", "curl"}
	for _, c := range checks {
		if !strings.Contains(out, c) {
			t.Errorf("output should contain %q\n%s", c, out)
		}
	}
}

func TestSetField_BoolTrue(t *testing.T) {
	path := writeTestCompose(t, testCompose)
	f := mustOpen(t, path)
	if err := f.SetField("web", "read_only", true); err != nil {
		t.Fatal(err)
	}
	f.Save()
	if !strings.Contains(readFile(t, f.path), "true") {
		t.Error("bool true should render as 'true'")
	}
}

func TestSetField_Integer(t *testing.T) {
	path := writeTestCompose(t, testCompose)
	f := mustOpen(t, path)
	if err := f.SetField("web", "replicas", 3); err != nil {
		t.Fatal(err)
	}
	f.Save()
	if !strings.Contains(readFile(t, f.path), "replicas: 3") {
		t.Error("int should render as '3'")
	}
}

func TestDeleteField(t *testing.T) {
	path := writeTestCompose(t, testCompose)
	f := mustOpen(t, path)
	if err := f.DeleteField("web", "privileged"); err != nil {
		t.Fatalf("DeleteField: %v", err)
	}
	f.Save()
	out := readFile(t, f.path)
	if strings.Contains(out, "privileged: true") {
		t.Errorf("output should not contain privileged\n%s", out)
	}
}

func TestDeleteField_NonExistent(t *testing.T) {
	path := writeTestCompose(t, testCompose)
	f := mustOpen(t, path)
	if err := f.DeleteField("web", "nonexistent"); err != nil {
		t.Errorf("DeleteField nonexistent should not error: %v", err)
	}
}

func TestDeleteField_NonExistentService(t *testing.T) {
	path := writeTestCompose(t, testCompose)
	f := mustOpen(t, path)
	if err := f.DeleteField("nonexistent", "foo"); err != nil {
		t.Errorf("DeleteField nonexistent service should not error: %v", err)
	}
}

func TestRemoveFromList(t *testing.T) {
	path := writeTestCompose(t, testCompose)
	f := mustOpen(t, path)
	if err := f.RemoveFromList("web", "cap_add", "SYS_ADMIN"); err != nil {
		t.Fatalf("RemoveFromList: %v", err)
	}
	f.Save()
	out := readFile(t, f.path)
	if strings.Contains(out, "SYS_ADMIN") {
		t.Errorf("SYS_ADMIN should be removed from cap_add\n%s", out)
	}
}

func TestRemoveFromList_NonExistentValue(t *testing.T) {
	path := writeTestCompose(t, testCompose)
	f := mustOpen(t, path)
	if err := f.RemoveFromList("web", "cap_add", "NOT_EXIST"); err != nil {
		t.Errorf("RemoveFromList nonexistent value should not error: %v", err)
	}
}

func TestRemoveFromList_NonExistentField(t *testing.T) {
	path := writeTestCompose(t, testCompose)
	f := mustOpen(t, path)
	if err := f.RemoveFromList("web", "nonexistent", "x"); err != nil {
		t.Errorf("RemoveFromList nonexistent field should not error: %v", err)
	}
}

func TestServiceNames(t *testing.T) {
	path := writeTestCompose(t, testCompose)
	f := mustOpen(t, path)
	names, err := f.ServiceNames()
	if err != nil {
		t.Fatalf("ServiceNames: %v", err)
	}
	if len(names) != 2 {
		t.Fatalf("ServiceNames = %v, want [web, db]", names)
	}
	if names[0] != "web" || names[1] != "db" {
		t.Errorf("ServiceNames = %v, want [web, db]", names)
	}
}

func TestServiceNames_Empty(t *testing.T) {
	path := writeTestCompose(t, "version: '3'")
	f := mustOpen(t, path)
	names, err := f.ServiceNames()
	if err != nil {
		t.Fatalf("ServiceNames: %v", err)
	}
	if len(names) != 0 {
		t.Errorf("no services should return empty slice, got %v", names)
	}
}

func TestBackup(t *testing.T) {
	path := writeTestCompose(t, testCompose)
	f := mustOpen(t, path)
	if err := f.Backup(); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	bakPath := path + ".bak"
	if _, err := os.Stat(bakPath); os.IsNotExist(err) {
		t.Error(".bak file was not created")
	}
}

func TestMultipleEdits(t *testing.T) {
	path := writeTestCompose(t, testCompose)
	f := mustOpen(t, path)

	if err := f.SetField("web", "privileged", false); err != nil {
		t.Fatal(err)
	}
	if err := f.SetField("web", "read_only", true); err != nil {
		t.Fatal(err)
	}
	if err := f.RemoveFromList("web", "cap_add", "SYS_ADMIN"); err != nil {
		t.Fatal(err)
	}
	if err := f.Save(); err != nil {
		t.Fatal(err)
	}

	out := readFile(t, f.path)
	for _, want := range []string{"privileged: false", "read_only: true"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output\n%s", want, out)
		}
	}
	if strings.Contains(out, "SYS_ADMIN") {
		t.Errorf("SYS_ADMIN should be removed\n%s", out)
	}
}

func TestGetFieldRaw(t *testing.T) {
	path := writeTestCompose(t, testCompose)
	f := mustOpen(t, path)
	val, err := f.GetFieldRaw("web", "image")
	if err != nil {
		t.Fatalf("GetFieldRaw: %v", err)
	}
	if val != "nginx:latest" {
		t.Errorf("GetFieldRaw(image) = %q, want nginx:latest", val)
	}
}

func TestGetFieldRaw_Missing(t *testing.T) {
	path := writeTestCompose(t, testCompose)
	f := mustOpen(t, path)
	val, err := f.GetFieldRaw("web", "nonexistent")
	if err != nil {
		t.Fatalf("GetFieldRaw: %v", err)
	}
	if val != "" {
		t.Errorf("GetFieldRaw(nonexistent) = %q, want empty", val)
	}
}


