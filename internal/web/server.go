package web

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"time"

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

	host := cfg.Host
	if host == "" {
		host = "127.0.0.1"
	}
	port := cfg.Port

	// No fallback: if the port is taken, forcefully reclaim it.
	addr := fmt.Sprintf("%s:%d", host, port)
	if err := tryBind(addr); err != nil {
		fmt.Printf("Port %d is in use, freeing it...\n", port)
		killPort(port)
		if err := tryBind(addr); err != nil {
			return fmt.Errorf("port %d still unavailable after freeing: %w", port, err)
		}
		fmt.Printf("Port %d freed successfully.\n", port)
	}
	portStr := strconv.Itoa(port)

	// Build the command ttyd will run: hostveil (auto-discovers compose files)
	childArgs := []string{self}

	// ttyd arguments
	ttydArgs := []string{
		"-p", portStr,
		"-W",
		"-t", "fontFamily=JetBrainsMono Nerd Font,JetBrainsMono,Fira Code,Consolas,monospace",
		"-t", "scrollback=0",
	}
	if host != "127.0.0.1" {
		ttydArgs = append(ttydArgs, "-i", host)
	}
	ttydArgs = append(ttydArgs, childArgs...)

	fmt.Printf("Hostveil web interface running on http://%s:%s/\n", host, portStr)
	fmt.Println("The TUI is streamed to your browser via ttyd (WebSocket terminal).")

	cmd := exec.Command(ttyd, ttydArgs...)
	cmd.Env = append(os.Environ(), "TERM=xterm-256color", "COLORTERM=truecolor")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// tryBind attempts to listen on addr and returns nil if successful.
func tryBind(addr string) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	l.Close()
	return nil
}

// killPort forcefully frees the given TCP port by killing the owning process.
// Tries multiple tools to handle different environments (host vs container).
func killPort(port int) {
	// Strategy 1: lsof (macOS, Linux with lsof installed)
	exec.Command("sh", "-c",
		fmt.Sprintf("lsof -ti :%d 2>/dev/null | xargs -r kill 2>/dev/null", port)).Run()
	time.Sleep(200 * time.Millisecond)

	// Strategy 2: fuser (Linux, often in minimal containers)
	exec.Command("sh", "-c",
		fmt.Sprintf("fuser -k %d/tcp 2>/dev/null", port)).Run()
	time.Sleep(200 * time.Millisecond)

	// Strategy 3: hard kill via lsof
	exec.Command("sh", "-c",
		fmt.Sprintf("lsof -ti :%d 2>/dev/null | xargs -r kill -9 2>/dev/null", port)).Run()
	time.Sleep(200 * time.Millisecond)

	// Strategy 4: hard kill via fuser
	exec.Command("sh", "-c",
		fmt.Sprintf("fuser -k -9 %d/tcp 2>/dev/null", port)).Run()
	time.Sleep(300 * time.Millisecond)
}
