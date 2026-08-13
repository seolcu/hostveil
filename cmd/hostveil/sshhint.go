package main

import (
	"fmt"
	"net"
	"strings"
)

// sshHint builds the command an operator runs on their *own* machine to reach
// a dashboard that is listening on the loopback interface of the host they are
// logged into.
//
// The question this answers is the one every SSH session ends at: `hostveil
// serve` printed http://127.0.0.1:8787/?t=… and 127.0.0.1 on a remote shell is
// the remote machine, so the URL was correct and useless. hostveil knew it was
// in an SSH session the whole time and said nothing.
//
// It does not open the dashboard to the network instead. The dashboard applies
// fixes as root, and binding it to a routable address would put that behind
// nothing but a token on a port anyone on the segment can reach. A forwarded
// port is the same access with the authentication already done.
//
// The host in the command is the address the client actually reached, read out
// of SSH_CONNECTION's third field, rather than the machine's hostname or an
// interface address. Those are guesses about what the client can route to;
// this one is the address a packet from that client demonstrably arrived on.
//
// Returns "" when this is not an SSH session, which is the ordinary console
// case and needs no advice.
func sshHint(getenv func(string) string, addr string) string {
	// "<client ip> <client port> <server ip> <server port>", set by sshd.
	fields := strings.Fields(getenv("SSH_CONNECTION"))
	if len(fields) < 4 {
		return ""
	}
	serverIP, serverPort := fields[2], fields[3]
	if net.ParseIP(serverIP) == nil {
		return ""
	}

	_, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return ""
	}

	// SUDO_USER first: serve auto-elevates, so by the time this runs the
	// process is root, and telling somebody to `ssh root@…` recommends a
	// login most hosts refuse and hostveil itself reports as a finding.
	user := firstNonEmpty(getenv("SUDO_USER"), getenv("USER"), getenv("LOGNAME"))

	dest := serverIP
	if strings.Contains(serverIP, ":") {
		// An IPv6 literal has to be bracketed here for the same reason it
		// does in a URL: the colons are already the field separator.
		dest = "[" + serverIP + "]"
	}
	if user != "" {
		dest = user + "@" + dest
	}

	cmd := "ssh -N"
	if serverPort != "22" {
		cmd += " -p " + serverPort
	}
	return fmt.Sprintf("%s -L %s:127.0.0.1:%s %s", cmd, port, port, dest)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
