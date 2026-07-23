package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/seolcu/hostveil/internal/ui/web"
)

func cmdServe(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	var addr string
	fs.StringVar(&addr, "addr", "127.0.0.1:8787", "address to bind the dashboard to")
	themeID := fs.String("theme", "", "color theme ("+themeList()+")")
	if code := parseFlags(fs, args); code >= 0 {
		return code
	}

	// The dashboard serves this as its starting palette; a choice made in the
	// browser's own picker is remembered per browser and overrides it.
	t, err := resolveTheme(*themeID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hostveil:", err)
		return 2
	}

	// What gates access is the Host header, not the bind address: the
	// dashboard answers only requests addressed to a loopback name, which is
	// the DNS-rebinding defense and is not negotiable from a flag.
	//
	// So the old warning — "binding to a non-loopback address exposes it to
	// the network" — was wrong in both directions. It does not expose the
	// dashboard, because a client that addresses this machine by IP or
	// hostname is refused. And it is not necessarily useless, because a
	// port-forward still works: the browser says localhost either way, which
	// is exactly how the Vagrant demo reaches it.
	if !strings.HasPrefix(addr, "127.0.0.1") && !strings.HasPrefix(addr, "localhost") {
		fmt.Fprintf(os.Stderr,
			"hostveil: bound to %s, but the dashboard still answers only requests addressed to localhost.\n"+
				"That works through a port-forward — the browser sends localhost either way — and refuses\n"+
				"anything that reaches this machine by IP or hostname. For remote access prefer an SSH\n"+
				"tunnel: ssh -L 8787:127.0.0.1:8787 you@this-host\n", addr)
	}

	srv := web.New(buildEngine(), addr, t.ID)
	// The URL carries a one-off access token, because loopback keeps the
	// dashboard off the network but not away from other accounts on this
	// machine — and every route here applies fixes or reads a scan of
	// /etc/shadow, as root.
	fmt.Printf("hostveil dashboard listening on %s  (scanning…)\n", addr)
	fmt.Printf("Open this exact URL — it carries the access token for this run:\n  %s\n", srv.URL())
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, "hostveil:", err)
		return 1
	}
	return 0
}
