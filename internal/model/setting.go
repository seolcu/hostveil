package model

// Setting is a single key/value pair inside a ConfigFile.
type Setting struct {
	ID              string `json:"id"`
	ConfigFileID    string `json:"config_file_id"`
	Line            int    `json:"line"`
	Key             string `json:"key"`
	RawValue        string `json:"raw_value"`
	EffectiveValue  string `json:"effective_value"`
	SafeValue       string `json:"safe_value,omitempty"`
}
