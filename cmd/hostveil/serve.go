package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/seolcu/hostveil/internal/ui/web"
)

func cmdServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	var addr string
	fs.StringVar(&addr, "addr", "127.0.0.1:8787", "address to bind the dashboard to")
	if code := parseFlags(fs, args); code >= 0 {
		return code
	}

	if !strings.HasPrefix(addr, "127.0.0.1") && !strings.HasPrefix(addr, "localhost") {
		fmt.Fprintln(os.Stderr, "hostveil: warning — binding the dashboard to a non-loopback address exposes it to the network.")
	}

	srv := web.New(buildEngine(), addr)
	fmt.Printf("hostveil dashboard on %s  (scanning…)\n", srv.URL())
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, "hostveil:", err)
		return 1
	}
	return 0
}
