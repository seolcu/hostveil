package compose

import (
	"strings"

	"gopkg.in/yaml.v3"
)

// VolumeMount represents a parsed service volume entry in either short or
// long Compose syntax.
type VolumeMount struct {
	Source string
	Target string
	Mode   string
	Raw    string
}

// GetVolumeMounts returns parsed volume mounts for a service, handling both
// short-syntax strings ("SOURCE:TARGET[:MODE]") and long-syntax maps
// (type/source/target/bind/read_only).
func (f *File) GetVolumeMounts(service string) []VolumeMount {
	node := f.walkPath(service, "volumes")
	if node == nil {
		return nil
	}
	switch node.Kind {
	case yaml.SequenceNode:
		var mounts []VolumeMount
		for _, item := range node.Content {
			if mount, ok := parseVolumeItem(item); ok {
				mounts = append(mounts, mount)
			}
		}
		return mounts
	case yaml.ScalarNode:
		if mount, ok := parseVolumeShort(node.Value); ok {
			return []VolumeMount{mount}
		}
	}
	return nil
}

func parseVolumeItem(item *yaml.Node) (VolumeMount, bool) {
	switch item.Kind {
	case yaml.ScalarNode:
		return parseVolumeShort(item.Value)
	case yaml.MappingNode:
		return parseVolumeLong(item)
	default:
		return VolumeMount{}, false
	}
}

func parseVolumeShort(v string) (VolumeMount, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return VolumeMount{}, false
	}
	source, mode, ok := splitShortVolume(v)
	if !ok {
		return VolumeMount{}, false
	}
	return VolumeMount{Source: source, Target: "", Mode: mode, Raw: v}, true
}

func splitShortVolume(v string) (source, mode string, ok bool) {
	parts := strings.Split(v, ":")
	if len(parts) < 2 {
		return "", "", false
	}
	source = parts[0]
	if len(parts) >= 3 {
		mode = parts[len(parts)-1]
	}
	return source, mode, true
}

func parseVolumeLong(item *yaml.Node) (VolumeMount, bool) {
	fields := mappingFields(item)
	volType := fields["type"]
	if volType == "" {
		volType = "volume"
	}
	source := fields["source"]
	if source == "" {
		source = fields["source_path"]
	}
	target := fields["target"]
	if target == "" {
		target = fields["destination"]
	}
	mode := fields["read_only"]
	if mode == "true" {
		mode = "ro"
	}
	raw := longVolumeRaw(source, target, mode, volType)
	switch volType {
	case "bind", "volume":
		if source == "" && target == "" {
			return VolumeMount{}, false
		}
		if source == "" {
			source = target
		}
		return VolumeMount{Source: source, Target: target, Mode: mode, Raw: raw}, true
	default:
		return VolumeMount{}, false
	}
}

func mappingFields(node *yaml.Node) map[string]string {
	out := make(map[string]string)
	for i := 0; i < len(node.Content)-1; i += 2 {
		key := node.Content[i].Value
		valNode := node.Content[i+1]
		switch valNode.Kind {
		case yaml.ScalarNode:
			out[key] = valNode.Value
		case yaml.MappingNode:
			if key == "bind" {
				for j := 0; j < len(valNode.Content)-1; j += 2 {
					out["bind."+valNode.Content[j].Value] = valNode.Content[j+1].Value
				}
			}
		}
	}
	return out
}

func longVolumeRaw(source, target, mode, volType string) string {
	if source != "" && target != "" {
		if mode == "ro" {
			return source + ":" + target + ":ro"
		}
		return source + ":" + target
	}
	if source != "" {
		return source
	}
	return volType + ":" + target
}

// SetVolumeReadOnly marks the targeted volume mount read-only. When
// targetVolume is empty every non-read-only mount on the service is
// updated. Short-syntax scalars get a :ro suffix; long-syntax maps get
// read_only: true. Returns true when at least one entry changed.
func (f *File) SetVolumeReadOnly(service, targetVolume string) (bool, error) {
	node := f.walkPath(service, "volumes")
	if node == nil || node.Kind != yaml.SequenceNode {
		return false, nil
	}
	changed := false
	for _, item := range node.Content {
		switch item.Kind {
		case yaml.ScalarNode:
			if !volumeScalarMatches(item.Value, targetVolume) {
				continue
			}
			if strings.Contains(item.Value, ":ro") {
				continue
			}
			item.Value = item.Value + ":ro"
			changed = true
		case yaml.MappingNode:
			mount, ok := parseVolumeLong(item)
			if !ok || !volumeMountMatches(mount, targetVolume) {
				continue
			}
			if hasVolumeMode(mount.Mode, "ro") || fieldsTrue(item, "read_only") {
				continue
			}
			setMappingScalar(item, "read_only", "true")
			changed = true
		}
	}
	if changed {
		f.dirty = true
	}
	return changed, nil
}

// RemoveVolumeMount drops the volume entry matching targetVolume from
// the service. Matching uses the same raw/source forms recorded in
// finding evidence. Returns true when an entry was removed.
func (f *File) RemoveVolumeMount(service, targetVolume string) (bool, error) {
	if targetVolume == "" {
		return false, nil
	}
	node := f.walkPath(service, "volumes")
	if node == nil || node.Kind != yaml.SequenceNode {
		return false, nil
	}
	var kept []*yaml.Node
	removed := false
	for _, item := range node.Content {
		if volumeItemMatches(item, targetVolume) {
			removed = true
			continue
		}
		kept = append(kept, item)
	}
	if removed {
		node.Content = kept
		f.dirty = true
	}
	return removed, nil
}

func volumeItemMatches(item *yaml.Node, targetVolume string) bool {
	switch item.Kind {
	case yaml.ScalarNode:
		return volumeScalarMatches(item.Value, targetVolume)
	case yaml.MappingNode:
		mount, ok := parseVolumeLong(item)
		return ok && volumeMountMatches(mount, targetVolume)
	default:
		return false
	}
}

func volumeScalarMatches(v, targetVolume string) bool {
	if targetVolume == "" {
		return true
	}
	if v == targetVolume {
		return true
	}
	prefix := strings.Split(targetVolume, ":")[0]
	return prefix != "" && strings.HasPrefix(v, prefix+":")
}

func volumeMountMatches(mount VolumeMount, targetVolume string) bool {
	if targetVolume == "" {
		return true
	}
	if mount.Raw == targetVolume {
		return true
	}
	pair := mount.Source + ":" + mount.Target
	if pair == targetVolume {
		return true
	}
	prefix := strings.Split(targetVolume, ":")[0]
	return prefix != "" && mount.Source == prefix
}

func fieldsTrue(item *yaml.Node, key string) bool {
	fields := mappingFields(item)
	return fields[key] == "true"
}

func hasVolumeMode(mode, want string) bool {
	for _, part := range strings.Split(mode, ",") {
		if strings.TrimSpace(part) == want {
			return true
		}
	}
	return false
}
