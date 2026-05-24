package web

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/seolcu/hostveil/internal/domain"
)

//go:embed assets/*
var assets embed.FS

type Options struct {
	Addr string
	Live *domain.ScanProgress
}

func Serve(opts Options) error {
	if opts.Addr == "" {
		opts.Addr = "127.0.0.1:8787"
	}
	if opts.Live == nil {
		opts.Live = domain.NewScanProgress(true)
	}
	if strings.HasPrefix(opts.Addr, "0.0.0.0:") || strings.HasPrefix(opts.Addr, ":") {
		fmt.Fprintln(os.Stderr, "  Warning: serving host scan results on a non-local address.")
	}

	listener, err := listenWithReclaim(opts.Addr)
	if err != nil {
		return err
	}
	defer listener.Close()

	staticFS, err := fs.Sub(assets, "assets")
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /api/result", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, opts.Live.Snapshot())
	})
	mux.Handle("/", http.FileServerFS(staticFS))

	server := &http.Server{
		Handler:           secureHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return server.Serve(listener)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func listenWithReclaim(addr string) (net.Listener, error) {
	listener, err := net.Listen("tcp", addr)
	if err == nil {
		return listener, nil
	}
	if !isAddrInUse(err) {
		return nil, err
	}

	host, portText, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		return nil, err
	}
	port, convErr := strconv.Atoi(portText)
	if convErr != nil {
		return nil, err
	}

	pids, reclaimErr := listenerPIDs(port)
	if reclaimErr != nil {
		return nil, fmt.Errorf("%s is in use and hostveil could not inspect the owning process: %w", addr, reclaimErr)
	}
	if len(pids) == 0 {
		return nil, fmt.Errorf("%s is in use but no listener process was found", addr)
	}

	self := os.Getpid()
	for pid := range pids {
		if pid == self {
			continue
		}
		fmt.Fprintf(os.Stderr, "  Port %d is in use; stopping process %d.\n", port, pid)
		_ = syscall.Kill(pid, syscall.SIGTERM)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		listener, err = net.Listen("tcp", net.JoinHostPort(host, portText))
		if err == nil {
			return listener, nil
		}
		if !isAddrInUse(err) {
			return nil, err
		}
		time.Sleep(100 * time.Millisecond)
	}

	for pid := range pids {
		if pid == self {
			continue
		}
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
	time.Sleep(200 * time.Millisecond)

	listener, err = net.Listen("tcp", net.JoinHostPort(host, portText))
	if err != nil {
		return nil, err
	}
	return listener, nil
}

func isAddrInUse(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		var sysErr *os.SyscallError
		if errors.As(opErr.Err, &sysErr) {
			return errors.Is(sysErr.Err, syscall.EADDRINUSE)
		}
	}
	return errors.Is(err, syscall.EADDRINUSE)
}

func listenerPIDs(port int) (map[int]struct{}, error) {
	inodes := map[string]struct{}{}
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		found, err := listenerInodes(path, port)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		for inode := range found {
			inodes[inode] = struct{}{}
		}
	}

	pids := map[int]struct{}{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join("/proc", entry.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
			if _, ok := inodes[inode]; ok {
				pids[pid] = struct{}{}
			}
		}
	}
	return pids, nil
}

func listenerInodes(path string, port int) (map[string]struct{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	inodes := map[string]struct{}{}
	lines := strings.Split(string(data), "\n")
	portHex := fmt.Sprintf("%04X", port)
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		local := fields[1]
		state := fields[3]
		if state != "0A" {
			continue
		}
		_, localPort, ok := strings.Cut(local, ":")
		if !ok || !strings.EqualFold(localPort, portHex) {
			continue
		}
		inodes[fields[9]] = struct{}{}
	}
	return inodes, nil
}
