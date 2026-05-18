package compose

type ComposeFile struct {
	Version  string
	Services map[string]Service
	Volumes  map[string]Volume
	Networks map[string]Network
}

type Service struct {
	Image       string
	Container   string
	User        string
	Ports       []Port
	Volumes     []VolumeMount
	Environment map[string]string
	EnvFile     []string
	CapAdd      []string
	CapDrop     []string
	Privileged  bool
	ReadOnly    bool
	NetworkMode string
	Labels      map[string]string
	DependsOn   []string
	Restart     string
	Command     string
}

type Port struct {
	Published uint16
	Target    uint16
	Protocol  string
	HostIP    string
}

type VolumeMount struct {
	Source   string
	Target   string
	ReadOnly bool
}

type Volume struct {
	Driver string
}

type Network struct {
	Driver     string
	External   bool
}
