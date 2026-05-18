package web

import (
	"fmt"
	"net"
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

	// Find an available port, starting from the requested one
	port := findPort(cfg.Host, cfg.Port)
	if port != cfg.Port {
		fmt.Printf("Port %d is in use, falling back to port %d\n", cfg.Port, port)
	}
	portStr := strconv.Itoa(port)

	host := cfg.Host
	if host == "" {
		host = "127.0.0.1"
	}

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
	ttydArgs := []string{"-p", portStr}
	if host != "127.0.0.1" {
		ttydArgs = append(ttydArgs, "-i", host)
	}
	ttydArgs = append(ttydArgs, childArgs...)

	fmt.Printf("Hostveil web interface running on http://%s:%d/\n", host, port)
	fmt.Println("The TUI is streamed to your browser via ttyd (WebSocket terminal).")

	cmd := exec.Command(ttyd, ttydArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// findPort tries the given port and increments until it finds an available one.
func findPort(host string, start int) int {
	for port := start; port < start+100; port++ {
		addr := fmt.Sprintf("%s:%d", host, port)
		l, err := net.Listen("tcp", addr)
		if err == nil {
			l.Close()
			return port
		}
	}
	// Last resort: let the OS assign one
	l, err := net.Listen("tcp", fmt.Sprintf("%s:0", host))
	if err != nil {
		return start // give up, let ttyd fail with its own error
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}
