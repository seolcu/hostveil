package web

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"github.com/seolcu/hostveil/internal/config"
)

func Serve(cfg *config.Config) error {
	ttyd, err := exec.LookPath("ttyd")
	if err != nil {
		return fmt.Errorf("ttyd not found. Install:\n" +
			"  brew install ttyd          # macOS\n" +
			"  sudo apt install ttyd       # Debian/Ubuntu\n" +
			"  sudo dnf install ttyd       # Fedora\n" +
			"  go install github.com/tsl0922/ttyd@latest")
	}

	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}

	port := strconv.Itoa(cfg.Port)
	host := cfg.Host

	// Build the command ttyd will run: hostveil with original args minus --serve
	childArgs := []string{self}
	if cfg.ComposePath != "" {
		childArgs = append(childArgs, "--compose", cfg.ComposePath)
	}
	if cfg.HostRoot != "" {
		childArgs = append(childArgs, "--host-root", cfg.HostRoot)
	}
	childArgs = append(childArgs, "--user-mode")

	// ttyd arguments
	ttydArgs := []string{"-p", port}
	if host != "127.0.0.1" {
		ttydArgs = append(ttydArgs, "-i", host)
	}
	ttydArgs = append(ttydArgs, childArgs...)

	fmt.Printf("Hostveil web interface running on http://%s:%s/\n", host, port)
	fmt.Println("The TUI is streamed to your browser via ttyd (WebSocket terminal).")

	cmd := exec.Command(ttyd, ttydArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
