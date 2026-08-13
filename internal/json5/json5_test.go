package json5

import (
	"reflect"
	"strings"
	"testing"
)

// The whole reason this package exists: an operator's comments are still
// there afterwards, and a one-key change is a one-line diff.
func TestSetKeepsEverythingItWasNotAskedToChange(t *testing.T) {
	src := `{
  // The gateway is reachable from the tailnet only.
  "gateway": {
    "port": 18789,      // default
    "controlUi": {
      /* turned on while debugging pairing, remember to remove */
      "allowInsecureAuth": true,
    },
  },
  "tools": { "exec": { "security": "full" } },
}
`
	d, err := Load([]byte(src))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := d.Set("gateway.controlUi.allowInsecureAuth", false); err != nil {
		t.Fatalf("Set: %v", err)
	}
	out, err := d.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}

	got := string(out)
	for _, keep := range []string{
		"// The gateway is reachable from the tailnet only.",
		"// default",
		"/* turned on while debugging pairing, remember to remove */",
		`"security": "full"`,
		"18789",
	} {
		if !strings.Contains(got, keep) {
			t.Errorf("edit dropped %q from the config:\n%s", keep, got)
		}
	}
	if !strings.Contains(got, `"allowInsecureAuth": false,`) {
		t.Errorf("value not replaced, or the trailing comma was eaten:\n%s", got)
	}

	// Exactly one line differs. A fix that reflows a config the operator
	// maintains is a fix whose diff nobody can review.
	if n := changedLines(src, got); n != 1 {
		t.Errorf("changed %d lines, want 1:\n%s", n, got)
	}
}

func changedLines(before, after string) int {
	b, a := strings.Split(before, "\n"), strings.Split(after, "\n")
	if len(b) != len(a) {
		return -1
	}
	n := 0
	for i := range b {
		if b[i] != a[i] {
			n++
		}
	}
	return n
}

func TestSetRewritesTheRightScalarKinds(t *testing.T) {
	cases := []struct {
		name string
		src  string
		path string
		v    any
		want string
	}{
		{"string", `{"tools":{"exec":{"security":"full"}}}`, "tools.exec.security", "deny", `{"tools":{"exec":{"security":"deny"}}}`},
		{"bool", `{"tools":{"elevated":{"enabled":true}}}`, "tools.elevated.enabled", false, `{"tools":{"elevated":{"enabled":false}}}`},
		{"bare key", `{tools:{exec:{security:'x'}}}`, "tools.exec.security", "deny", ""},
		{"single-quoted value", `{"a":'full'}`, "a", "deny", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := Load([]byte(tc.src))
			if err != nil {
				// Single quotes and bare keys are JSON5 the locator
				// understands but encoding/json cannot decode, so Load
				// refuses them. That is the honest outcome: the checker
				// could not read such a file either, so there is no
				// finding for a fix to serve.
				t.Skipf("not decodable, so not fixable: %v", err)
			}
			if err := d.Set(tc.path, tc.v); err != nil {
				t.Fatalf("Set: %v", err)
			}
			out, err := d.Bytes()
			if err != nil {
				t.Fatalf("Bytes: %v", err)
			}
			if tc.want != "" && string(out) != tc.want {
				t.Errorf("got %s, want %s", out, tc.want)
			}
		})
	}
}

func TestSetRefusesAPathThatIsNotThere(t *testing.T) {
	d, err := Load([]byte(`{"gateway":{"port":18789}}`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if d.Has("gateway.controlUi.allowInsecureAuth") {
		t.Fatal("Has reported a path this config does not contain")
	}
	err = d.Set("gateway.controlUi.allowInsecureAuth", false)
	if err == nil {
		t.Fatal("Set created a key path; it must only replace one that exists")
	}
	if !strings.Contains(err.Error(), "not present") {
		t.Errorf("error should say the path is absent, got: %v", err)
	}
}

// A key with a literal dot in it spells the same dotted path as a nested one,
// and neither this package nor the checker's lookup can tell them apart. The
// answer is to refuse, not to edit whichever was recorded last.
func TestAmbiguousDottedKeyIsRefused(t *testing.T) {
	d, err := Load([]byte(`{"a":{"b":1},"a.b":2}`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if d.Has("a.b") {
		t.Fatal("Has accepted an ambiguous path")
	}
	if err := d.Set("a.b", 3); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Errorf("want an ambiguity error, got %v", err)
	}
}

// A "//" inside a string is not a comment, and a value containing braces must
// not end the object early. Both would corrupt a config silently.
func TestStringContentsAreNotStructure(t *testing.T) {
	src := `{"a":"https://example.com/x","b":"} not the end {","c":true}`
	d, err := Load([]byte(src))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := d.Set("c", false); err != nil {
		t.Fatalf("Set: %v", err)
	}
	out, err := d.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	want := `{"a":"https://example.com/x","b":"} not the end {","c":false}`
	if string(out) != want {
		t.Errorf("got %s, want %s", out, want)
	}
}

func TestNoEditsReturnsTheSourceUnchanged(t *testing.T) {
	src := []byte("{\n  // hello\n  \"a\": 1,\n}\n")
	d, err := Load(src)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	out, err := d.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	if string(out) != string(src) {
		t.Errorf("an unedited document was rewritten:\n%s", out)
	}
}

// FuzzJSON5Edit holds the package's central promise against arbitrary input:
// an edit either fails outright or produces a document that decodes to the
// original tree with exactly the one key changed. Silently changing anything
// else is the failure this exists to catch, because the file being edited is
// the operator's own and there is no re-encode to fall back to.
func FuzzJSON5Edit(f *testing.F) {
	f.Add(`{"a":1,"b":{"c":true}}`, "b.c")
	f.Add("{\n  // note\n  \"a\": \"x\", /* t */\n}\n", "a")
	f.Add(`{"a":{"b":{"c":"deep"}},"d":[1,2,{"e":false}]}`, "a.b.c")
	f.Add(`{"a":"//not a comment"}`, "a")
	f.Add(`{"a":1,}`, "a")

	f.Fuzz(func(t *testing.T, src, path string) {
		d, err := Load([]byte(src))
		if err != nil {
			return // not a config, nothing to promise
		}
		if !d.Has(path) {
			return
		}
		before := cloneTree(d.tree)
		if err := d.Set(path, "hostveil-fuzz"); err != nil {
			t.Fatalf("Set on a path Has accepted: %v", err)
		}
		out, err := d.Bytes()
		if err != nil {
			return // refusing is always allowed; writing something wrong is not
		}
		got, err := Decode(out)
		if err != nil {
			t.Fatalf("Bytes returned a document that does not parse: %v\nin:  %s\nout: %s", err, src, out)
		}
		want := before
		if err := assign(want, path, "hostveil-fuzz"); err != nil {
			t.Fatalf("assign on a located path: %v", err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("edit changed more than %q\nin:   %s\nout:  %s\nwant: %v\ngot:  %v", path, src, out, want, got)
		}
	})
}
