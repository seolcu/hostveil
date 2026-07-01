package history

import (
	"fmt"
	"os"
	"os/exec"
)

// RollbackResult contains the outcome of a rollback operation.
type RollbackResult struct {
	RestoredFiles []string `json:"restored_files"`
	Restart       *Restart `json:"restart,omitempty"`
	Message       string   `json:"message"`
}

// Rollback restores files from a checkpoint.
// It does NOT automatically restart services — the caller must handle that.
func Rollback(cp Checkpoint) (*RollbackResult, error) {
	result := &RollbackResult{}

	for _, backup := range cp.Backups {
		data, err := os.ReadFile(backup.BackupPath)
		if err != nil {
			return nil, fmt.Errorf("read backup %s: %w", backup.BackupPath, err)
		}
		if err := os.WriteFile(backup.OriginalPath, data, os.FileMode(backup.Mode)); err != nil {
			return nil, fmt.Errorf("restore %s: %w", backup.OriginalPath, err)
		}
		result.RestoredFiles = append(result.RestoredFiles, backup.OriginalPath)
	}

	result.Restart = cp.Restart
	if len(result.RestoredFiles) == 0 {
		result.Message = "No files to restore."
	} else if cp.Restart != nil {
		result.Message = fmt.Sprintf("Restored %d file(s). Service restart may be needed.", len(result.RestoredFiles))
	} else {
		result.Message = fmt.Sprintf("Restored %d file(s).", len(result.RestoredFiles))
	}

	return result, nil
}

// RestartService attempts to restart a service.
// Returns a user-friendly message about what to do.
func RestartService(r Restart) (string, error) {
	if len(r.Command) == 0 {
		return fmt.Sprintf("Please manually restart: %s", r.Description), nil
	}

	// r.Command is a []string passed directly to exec.Command — no shell
	// interpretation, so a malicious service name can't inject extra
	// arguments or shell metacharacters.
	out, err := exec.Command(r.Command[0], r.Command[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Automatic restart failed (%v). Please run manually: %v\nOutput: %s", err, r.Command, string(out)), err
	}
	return fmt.Sprintf("Restarted %s successfully.", r.ServiceName), nil
}

// RestartForService returns the appropriate Restart config for common service names.
func RestartForService(service string) *Restart {
	switch {
	case service == "sshd" || service == "ssh":
		return &Restart{
			ServiceName: "sshd",
			Command:     []string{"sh", "-c", "systemctl restart sshd || service sshd restart || service ssh restart"},
			Description: "Restart SSH daemon",
		}
	case service == "sysctl" || service == "":
		return nil // sysctl changes take effect immediately
	default:
		return &Restart{
			ServiceName: service,
			Command:     []string{"docker", "compose", "restart", service},
			Description: fmt.Sprintf("Restart container %s", service),
		}
	}
}
