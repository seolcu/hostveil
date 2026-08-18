package fix

import (
	"bytes"
	"fmt"
	"regexp"

	"github.com/seolcu/hostveil/internal/model"
)

func registerAccounts(r *Registry) {
	r.Register("accounts.password-rounds", buildLoginDefaults("Harden password hashing rounds", []loginDefault{{"SHA_CRYPT_MIN_ROUNDS", "5000"}, {"SHA_CRYPT_MAX_ROUNDS", "10000"}}))
	r.Register("accounts.default-umask", buildLoginDefaults("Set the default umask to 027", []loginDefault{{"UMASK", "027"}}))
	r.Register("accounts.password-aging", buildLoginDefaults("Harden password aging defaults", []loginDefault{{"PASS_MIN_DAYS", "1"}, {"PASS_MAX_DAYS", "365"}}))
	r.Register("accounts.core-dumps", buildCoreDumpLimit)
	r.Register("accounts.local-banner", buildAccessBanner)
	r.Register("accounts.remote-banner", buildAccessBanner)
}

func buildCoreDumpLimit(f model.Finding) (Fix, error) {
	path := f.Evidence["config"]
	if path == "" {
		return Fix{}, fmt.Errorf("finding %s names no limits path", f.ID)
	}
	return Fix{Label: "Disable core dumps through PAM limits", Kind: model.RemediationAuto, Actions: []Action{{Label: "Set a hard core-size limit of zero", Kind: ActionEdit, Path: path, Transform: func(in []byte) ([]byte, error) {
		if hasCoreLimit(in) {
			return in, nil
		}
		out := append([]byte(nil), bytes.TrimRight(in, "\n")...)
		if len(out) > 0 {
			out = append(out, '\n')
		}
		return append(out, []byte("* hard core 0\n")...), nil
	}}}}, nil
}

func hasCoreLimit(data []byte) bool {
	for _, line := range bytes.Split(data, []byte("\n")) {
		fields := bytes.Fields(bytes.SplitN(line, []byte("#"), 2)[0])
		if len(fields) == 4 && bytes.Equal(fields[0], []byte("*")) && bytes.Equal(fields[1], []byte("hard")) && bytes.Equal(fields[2], []byte("core")) && bytes.Equal(fields[3], []byte("0")) {
			return true
		}
	}
	return false
}

type loginDefault struct{ key, value string }

func buildLoginDefaults(label string, values []loginDefault) Builder {
	return func(f model.Finding) (Fix, error) {
		path := f.Evidence["config"]
		if path == "" {
			return Fix{}, fmt.Errorf("finding %s names no login.defs path", f.ID)
		}
		return Fix{Label: label, Kind: model.RemediationAuto, Actions: []Action{{Label: label, Kind: ActionEdit, Path: path, Transform: func(in []byte) ([]byte, error) {
			out := in
			for _, setting := range values {
				re := regexp.MustCompile(`(?m)^[ \t]*#?[ \t]*` + regexp.QuoteMeta(setting.key) + `[ \t]+.*$`)
				line := []byte(setting.key + " " + setting.value)
				if re.Match(out) {
					out = re.ReplaceAll(out, line)
				} else {
					out = append(bytes.TrimRight(out, "\n"), append([]byte("\n"), append(line, '\n')...)...)
				}
			}
			return out, nil
		}}}}, nil
	}
}

const accessWarning = "WARNING: Authorized access only. Activity may be monitored and recorded. Unauthorized use is prohibited and may be reported."

func buildAccessBanner(f model.Finding) (Fix, error) {
	path := f.Evidence["config"]
	if path == "" {
		return Fix{}, fmt.Errorf("finding %s names no banner path", f.ID)
	}
	return Fix{Label: "Add a pre-login access warning", Kind: model.RemediationAuto, Actions: []Action{{Label: "Append the standard access warning", Warning: "Have counsel or the system owner approve login-banner wording for this organization.", Kind: ActionEdit, Path: path, CreateIfMissing: true, Transform: func(in []byte) ([]byte, error) {
		if bytes.Contains(bytes.ToLower(in), []byte("authorized access only")) {
			return in, nil
		}
		out := append([]byte(nil), bytes.TrimRight(in, "\n")...)
		if len(out) > 0 {
			out = append(out, '\n')
		}
		return append(out, []byte(accessWarning+"\n")...), nil
	}}}}, nil
}
