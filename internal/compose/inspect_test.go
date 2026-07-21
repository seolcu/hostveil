package compose

import "testing"

// A realistic `docker inspect` array: one hand-started container and one
// created by Compose.
const twoContainers = `[
 {
  "Name": "/cache",
  "Config": {
   "Image": "redis:alpine",
   "User": "",
   "Env": ["PATH=/usr/local/bin", "REDIS_PASSWORD=hunter2"],
   "Labels": {"maintainer": "me"},
   "Healthcheck": null
  },
  "HostConfig": {
   "Privileged": true,
   "NetworkMode": "bridge",
   "CapAdd": ["SYS_ADMIN"],
   "SecurityOpt": null,
   "Binds": ["/etc:/host-etc:rw", "mydata:/data"],
   "Memory": 0,
   "PortBindings": {"6379/tcp": [{"HostIp": "0.0.0.0", "HostPort": "6379"}]},
   "RestartPolicy": {"Name": "no"}
  }
 },
 {
  "Name": "/media-jellyfin-1",
  "Config": {
   "Image": "jellyfin/jellyfin:latest",
   "Labels": {"com.docker.compose.project": "media"}
  },
  "HostConfig": {"NetworkMode": "bridge", "RestartPolicy": {"Name": "unless-stopped"}}
 }
]`

// Compose-managed containers are already audited through their compose file.
// Including them here would report every finding twice — once fixable, once
// not — which is worse than not seeing them at all.
func TestComposeManagedContainersAreExcluded(t *testing.T) {
	cs, err := parseInspect([]byte(twoContainers))
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 1 {
		t.Fatalf("want 1 standalone container, got %d: %+v", len(cs), cs)
	}
	if cs[0].Name != "cache" {
		t.Errorf("name = %q, want cache (leading slash stripped)", cs[0].Name)
	}
}

func TestInspectMapsSecurityRelevantFields(t *testing.T) {
	cs, err := parseInspect([]byte(twoContainers))
	if err != nil {
		t.Fatal(err)
	}
	s := cs[0].Service

	if !s.Privileged {
		t.Error("Privileged not mapped")
	}
	if s.Image != "redis:alpine" {
		t.Errorf("Image = %q", s.Image)
	}
	if len(s.CapAdd) != 1 || s.CapAdd[0] != "SYS_ADMIN" {
		t.Errorf("CapAdd = %v", s.CapAdd)
	}
	if s.Restart != "no" {
		t.Errorf("Restart = %q", s.Restart)
	}
	if s.Healthcheck != nil {
		t.Error("a null healthcheck must stay nil so the rule fires")
	}

	// The port is published on all interfaces — the thing that makes a
	// datastore reachable from the internet.
	if len(s.Ports) != 1 {
		t.Fatalf("Ports = %+v", s.Ports)
	}
	if !s.Ports[0].ExposedOnAllInterfaces() {
		t.Errorf("0.0.0.0:6379 should read as exposed, got %+v", s.Ports[0])
	}

	// /etc mounted read-write is a bind; a named volume is not, so the
	// sensitive-path rule never considers it.
	if len(s.Volumes) != 2 {
		t.Fatalf("Volumes = %+v", s.Volumes)
	}
	etc, data := s.Volumes[0], s.Volumes[1]
	if !etc.Bind || etc.ReadOnly || etc.Source != "/etc" {
		t.Errorf("/etc bind mapped wrong: %+v", etc)
	}
	if data.Bind {
		t.Errorf("named volume %q must not be treated as a host bind", data.Source)
	}
}

func TestReadOnlyBindDetected(t *testing.T) {
	in := `[{"Name":"/x","Config":{"Image":"a"},"HostConfig":{"Binds":["/var/run/docker.sock:/var/run/docker.sock:ro"]}}]`
	cs, err := parseInspect([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	v := cs[0].Service.Volumes[0]
	if !v.ReadOnly {
		t.Errorf(":ro not detected: %+v", v)
	}
}

// Docker writes bind options as a comma-joined list ("rw,z" under SELinux),
// so :ro has to be found inside it rather than compared to the whole field.
func TestReadOnlyInsideCommaJoinedOptions(t *testing.T) {
	in := `[{"Name":"/x","Config":{"Image":"a"},"HostConfig":{"Binds":["/etc:/etc:ro,z"]}}]`
	cs, err := parseInspect([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if !cs[0].Service.Volumes[0].ReadOnly {
		t.Error("ro not detected inside a comma-joined option list")
	}
}

// A container port with no host binding is not reachable from the host, so
// it must not read as published.
func TestUnpublishedPortNotMarkedPublished(t *testing.T) {
	in := `[{"Name":"/x","Config":{"Image":"a"},"HostConfig":{"PortBindings":{"80/tcp":null,"443/tcp":[{"HostIp":"","HostPort":""}]}}}]`
	cs, err := parseInspect([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if n := len(cs[0].Service.Ports); n != 0 {
		t.Errorf("want no published ports, got %d: %+v", n, cs[0].Service.Ports)
	}
}

// PortBindings is a map, so iteration order is random. Findings carry these
// values as evidence, and unstable evidence makes every rescan report a
// change nobody made.
func TestPortOrderIsStable(t *testing.T) {
	in := `[{"Name":"/x","Config":{"Image":"a"},"HostConfig":{"PortBindings":{
	 "80/tcp":[{"HostIp":"0.0.0.0","HostPort":"8080"}],
	 "443/tcp":[{"HostIp":"0.0.0.0","HostPort":"8443"}],
	 "22/tcp":[{"HostIp":"0.0.0.0","HostPort":"2222"}]}}}]`
	var first []string
	for i := 0; i < 20; i++ {
		cs, err := parseInspect([]byte(in))
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, p := range cs[0].Service.Ports {
			got = append(got, p.HostPort)
		}
		if first == nil {
			first = got
			continue
		}
		for j := range got {
			if got[j] != first[j] {
				t.Fatalf("port order varies between runs: %v vs %v", first, got)
			}
		}
	}
}

func TestMemoryLimitMapped(t *testing.T) {
	in := `[{"Name":"/x","Config":{"Image":"a"},"HostConfig":{"Memory":536870912}}]`
	cs, err := parseInspect([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if cs[0].Service.MemLimit != "536870912" {
		t.Errorf("MemLimit = %q", cs[0].Service.MemLimit)
	}

	unlimited := `[{"Name":"/x","Config":{"Image":"a"},"HostConfig":{"Memory":0}}]`
	cs, err = parseInspect([]byte(unlimited))
	if err != nil {
		t.Fatal(err)
	}
	if cs[0].Service.MemLimit != "" {
		t.Errorf("Memory 0 means unlimited and must stay empty, got %q", cs[0].Service.MemLimit)
	}
}

func TestHealthcheckPresenceMapped(t *testing.T) {
	in := `[{"Name":"/x","Config":{"Image":"a","Healthcheck":{"Test":["CMD-SHELL","curl -f localhost"]}},"HostConfig":{}}]`
	cs, err := parseInspect([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if cs[0].Service.Healthcheck == nil {
		t.Error("a defined healthcheck should be mapped as present")
	}

	// An entry of {"Test": ["NONE"]}... is still a Test list, but an empty
	// one means no healthcheck at all.
	empty := `[{"Name":"/x","Config":{"Image":"a","Healthcheck":{"Test":[]}},"HostConfig":{}}]`
	cs, err = parseInspect([]byte(empty))
	if err != nil {
		t.Fatal(err)
	}
	if cs[0].Service.Healthcheck != nil {
		t.Error("an empty Test list is not a healthcheck")
	}
}

func TestContainerOrderIsStable(t *testing.T) {
	in := `[{"Name":"/zeta","Config":{"Image":"a"},"HostConfig":{}},
	        {"Name":"/alpha","Config":{"Image":"b"},"HostConfig":{}}]`
	cs, err := parseInspect([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if cs[0].Name != "alpha" || cs[1].Name != "zeta" {
		t.Errorf("containers not sorted by name: %v, %v", cs[0].Name, cs[1].Name)
	}
}

func TestMalformedInspectOutputIsAnError(t *testing.T) {
	if _, err := parseInspect([]byte("not json")); err == nil {
		t.Error("malformed docker inspect output must be an error, not an empty clean result")
	}
}
