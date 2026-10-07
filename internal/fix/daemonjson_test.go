package fix

import "testing"

func TestSetJSONKeyKeepsTheRestOfTheFile(t *testing.T) {
	for _, tc := range []struct{ name, in, key, raw, want string }{
		{"empty file", "", "live-restore", "true", "{\n  \"live-restore\": true\n}\n"},
		{"empty object", "{}\n", "live-restore", "true", "{\n  \"live-restore\": true\n}\n"},
		{"insert after members",
			"{\n    \"log-driver\": \"journald\",\n    \"storage-driver\": \"overlay2\"\n}\n",
			"no-new-privileges", "true",
			"{\n    \"log-driver\": \"journald\",\n    \"storage-driver\": \"overlay2\",\n    \"no-new-privileges\": true\n}\n"},
		{"replace in place",
			"{\n  \"live-restore\": false,\n  \"debug\": true\n}\n",
			"live-restore", "true",
			"{\n  \"live-restore\": true,\n  \"debug\": true\n}\n"},
		{"replace an array",
			"{\"hosts\": [\"tcp://0.0.0.0:2375\", \"unix:///var/run/docker.sock\"], \"debug\": true}",
			"hosts", `["unix:///var/run/docker.sock"]`,
			"{\"hosts\": [\"unix:///var/run/docker.sock\"], \"debug\": true}"},
	} {
		got, err := setJSONKey([]byte(tc.in), tc.key, tc.raw)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if string(got) != tc.want {
			t.Errorf("%s:\n got %q\nwant %q", tc.name, got, tc.want)
		}
	}
}

// A nested key of the same name is not the top-level one.
func TestSetJSONKeyIgnoresNestedKeys(t *testing.T) {
	in := "{\n  \"log-opts\": {\"live-restore\": \"x\"}\n}\n"
	got, err := setJSONKey([]byte(in), "live-restore", "true")
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"log-opts\": {\"live-restore\": \"x\"},\n  \"live-restore\": true\n}\n"
	if string(got) != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestSetJSONKeyRefusesWhatItCannotRead(t *testing.T) {
	for _, in := range []string{"[1,2]", "{\"a\": ", "// comment\n{}"} {
		if _, err := setJSONKey([]byte(in), "k", "true"); err == nil {
			t.Errorf("%q: want an error", in)
		}
	}
	if _, err := setJSONKey([]byte("{}"), "k", "not json"); err == nil {
		t.Error("a raw value that is not JSON must be refused")
	}
}
