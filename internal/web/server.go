// Package web provides the embedded HTTP server and Web UI.
package web

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/seolcu/hostveil/internal/domain"
	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/scan"
)

//go:embed assets/*
var assets embed.FS

type Options struct {
	Addr     string
	Live     *domain.ScanProgress
	Fixes    *fix.Registry
	CertFile string
	KeyFile  string
	RescanFn func()
	rescanMu *sync.Mutex
}

func Serve(opts Options) error {
	if opts.rescanMu == nil {
		opts.rescanMu = &sync.Mutex{}
	}
	if opts.Addr == "" {
		opts.Addr = "127.0.0.1:8787"
	}
	if opts.Live == nil {
		opts.Live = domain.NewScanProgress(true)
	}
	if os.Getenv("HOSTVEIL_TEST") == "" {
		if strings.HasPrefix(opts.Addr, "0.0.0.0:") || strings.HasPrefix(opts.Addr, ":") {
			fmt.Fprintln(os.Stderr, "  Warning: serving host scan results on a non-local address.")
		}
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
	mux.HandleFunc("POST /api/fix", func(w http.ResponseWriter, r *http.Request) {
		handleFix(w, r, opts)
	})
	mux.HandleFunc("POST /api/fix/batch", func(w http.ResponseWriter, r *http.Request) {
		handleFixBatch(w, r, opts)
	})
	mux.HandleFunc("POST /api/rescan", func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && !sameOrigin(origin, r.Host) {
			writeJSON(w, map[string]interface{}{"success": false, "error": "rejected: cross-origin request"})
			return
		}
		handleRescan(w, r, opts)
	})
	mux.HandleFunc("GET /api/export", func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && !sameOrigin(origin, r.Host) {
			writeJSON(w, map[string]interface{}{"success": false, "error": "rejected: cross-origin request"})
			return
		}
		handleExport(w, r, opts.Live)
	})
	mux.Handle("/", http.FileServerFS(staticFS))

	server := &http.Server{
		Handler:           secureHeaders(mux),
		ReadHeaderTimeout: domain.HTTPReadHeaderTimeout,
	}
	if opts.CertFile != "" && opts.KeyFile != "" {
		return server.ServeTLS(listener, opts.CertFile, opts.KeyFile)
	}
	return server.Serve(listener)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(os.Stderr, "hostveil web: writeJSON: %v\n", err)
	}
}

func sameOrigin(origin, host string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return u.Host == host && (u.Scheme == "http" || u.Scheme == "https")
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
		host, portText, splitErr := net.SplitHostPort(addr)
		if splitErr == nil && host == "127.0.0.1" {
			ipv6Addr := net.JoinHostPort("::1", portText)
			listener, err2 := net.Listen("tcp6", ipv6Addr)
			if err2 == nil {
				return listener, nil
			}
		}
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
		if !isHostveilProcess(pid) {
			fmt.Fprintf(os.Stderr, "  Port %d is in use by another process (PID %d); not stopping.\n", port, pid)
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
		if !isHostveilProcess(pid) {
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
	// Try /proc/net/tcp* first (Linux)
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
	if len(inodes) > 0 {
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
		if len(pids) > 0 {
			return pids, nil
		}
	}

	// Fallback: use lsof (macOS, or Linux without /proc)
	return listenerPIDsViaLsof(port)
}

func listenerPIDsViaLsof(port int) (map[int]struct{}, error) {
	out, err := exec.Command("lsof", "-i", fmt.Sprintf(":%d", port), "-t").Output()
	if err != nil {
		// lsof returns non-zero when no matches found
		return nil, nil
	}
	pids := map[int]struct{}{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(line))
		if err != nil {
			continue
		}
		pids[pid] = struct{}{}
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

func isHostveilProcess(pid int) bool {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return false
	}
	cmdline := strings.ReplaceAll(string(data), "\x00", " ")
	for _, field := range strings.Fields(cmdline) {
		base := filepath.Base(field)
		if base == "hostveil" {
			return true
		}
	}
	return false
}

type fixRequest struct {
	Finding     domain.Finding `json:"finding"`
	ActionIndex int            `json:"action_index"`
	InfoOnly    bool           `json:"info_only"`
}

func handleFix(w http.ResponseWriter, r *http.Request, opts Options) {
	reg := opts.Fixes
	if reg == nil {
		http.Error(w, `{"error":"fix engine not available"}`, http.StatusServiceUnavailable)
		return
	}
	origin := r.Header.Get("Origin")
	if origin != "" && !sameOrigin(origin, r.Host) {
		writeJSON(w, map[string]interface{}{"success": false, "error": "rejected: cross-origin request"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req fixRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]interface{}{"success": false, "error": "invalid request: " + err.Error()})
		return
	}

	f := reg.Lookup(req.Finding.ID)
	if f == nil {
		writeJSON(w, map[string]interface{}{"success": false, "error": "no fix registered for this finding"})
		return
	}

	if req.InfoOnly {
		actions := make([]map[string]interface{}, len(f.Actions))
		ctx := fix.Context{Finding: &req.Finding}
		for i, a := range f.Actions {
			actionInfo := map[string]interface{}{
				"index":   i,
				"type":    a.Type.String(),
				"label":   a.Label,
				"warning": a.Warning,
			}

			switch a.Type {
			case fix.ActionEdit:
				editPath := a.FilePath
				if editPath == "" {
					editPath = a.EditPath
				}
				if editPath == "" {
					editPath = ctx.ComposePath()
				}
				if editPath != "" {
					actionInfo["edit_path"] = editPath
				}
				diff, _ := fix.SimulateDiff(ctx, a)
				if diff != "" {
					actionInfo["diff_preview"] = diff
				}
			case fix.ActionExec:
				if len(a.Command) > 0 {
					actionInfo["command"] = strings.Join(a.Command, " ")
				}
			}

			actions[i] = actionInfo
		}
		writeJSON(w, map[string]interface{}{
			"success": true,
			"label":   f.Label,
			"actions": actions,
		})
		return
	}

	result := f.Run(fix.Context{Finding: &req.Finding, Log: func(s string, args ...interface{}) {}}, req.ActionIndex)
	resp := map[string]interface{}{
		"success": result.Success,
		"label":   result.Label,
	}
	if result.Error != "" {
		resp["error"] = result.Error
	}
	if result.Diff != "" {
		resp["diff"] = result.Diff
	}

	// Auto-mark related findings as Fixed (shared solution detection)
	if result.Success && opts.Live != nil {
		opts.Live.MarkFixed(req.Finding.ID)
		if req.Finding.Service != "" {
			alsoFixed := opts.Live.MarkRelatedFixed(req.Finding.ID, req.Finding.Service, func(id string) bool {
				return reg.Lookup(id) == f
			})
			if len(alsoFixed) > 0 {
				resp["also_fixed"] = alsoFixed
			}
		}
	}

	writeJSON(w, resp)
}

func handleRescan(w http.ResponseWriter, r *http.Request, opts Options) {
	if !opts.rescanMu.TryLock() {
		writeJSON(w, map[string]interface{}{"success": false, "error": "rescan already in progress"})
		return
	}
	opts.Live.ResetForRescan()
	go func() {
		defer opts.rescanMu.Unlock()
		if opts.RescanFn != nil {
			opts.RescanFn()
		} else {
			runRescan(opts)
		}
	}()
	writeJSON(w, map[string]string{"status": "rescanning"})
}

func runRescan(opts Options) {
	scan.RunSingleTool(opts.Live, opts.Fixes, "trivy")
	scan.RunSingleTool(opts.Live, opts.Fixes, "lynis")
	opts.Live.Finalize()
}

type fixBatchRequest struct {
	Findings    []domain.Finding `json:"findings"`
	ActionIndex int              `json:"action_index"`
}

func handleFixBatch(w http.ResponseWriter, r *http.Request, opts Options) {
	reg := opts.Fixes
	if reg == nil {
		http.Error(w, `{"error":"fix engine not available"}`, http.StatusServiceUnavailable)
		return
	}
	origin := r.Header.Get("Origin")
	if origin != "" && !sameOrigin(origin, r.Host) {
		writeJSON(w, map[string]interface{}{"success": false, "error": "rejected: cross-origin request"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req fixBatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]interface{}{"success": false, "error": "invalid request: " + err.Error()})
		return
	}

	results := make([]map[string]interface{}, 0, len(req.Findings))
	allAlsoFixed := make(map[string]bool)

	for _, finding := range req.Findings {
		f := reg.Lookup(finding.ID)
		if f == nil {
			results = append(results, map[string]interface{}{
				"id":      finding.ID,
				"success": false,
				"error":   "no fix registered",
			})
			continue
		}

		result := f.Run(fix.Context{Finding: &finding, Log: func(s string, args ...interface{}) {}}, req.ActionIndex)
		entry := map[string]interface{}{
			"id":      finding.ID,
			"success": result.Success,
			"label":   result.Label,
		}
		if result.Error != "" {
			entry["error"] = result.Error
		}
		if result.Diff != "" {
			entry["diff"] = result.Diff
		}

		// Auto-mark related findings
		if result.Success && opts.Live != nil {
			opts.Live.MarkFixed(finding.ID)
			if finding.Service != "" {
				alsoFixed := opts.Live.MarkRelatedFixed(finding.ID, finding.Service, func(id string) bool {
					return reg.Lookup(id) == f
				})
				for _, aid := range alsoFixed {
					allAlsoFixed[aid] = true
				}
			}
		}

		results = append(results, entry)
	}

	resp := map[string]interface{}{
		"results": results,
	}
	if len(allAlsoFixed) > 0 {
		alsoFixedList := make([]string, 0, len(allAlsoFixed))
		for id := range allAlsoFixed {
			alsoFixedList = append(alsoFixedList, id)
		}
		resp["also_fixed"] = alsoFixedList
	}

	writeJSON(w, resp)
}

func handleExport(w http.ResponseWriter, r *http.Request, live *domain.ScanProgress) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	snap := live.Snapshot()

	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=hostveil-report.csv")
		var buf strings.Builder
		buf.WriteString("ID,Severity,Source,Service,Title,Remediation,Fixed\n")
		for _, f := range snap.Findings {
			buf.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s,%s,%v\n",
				domain.EscapeCSV(f.ID), f.Severity.String(), f.Source.String(), domain.EscapeCSV(f.Service),
				domain.EscapeCSV(f.Title), f.Remediation.String(), f.Fixed))
		}
		w.Write([]byte(buf.String()))
	default:
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=hostveil-report.json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(snap)
	}
}
