package ssl

import (
	"net"
	"time"
)

// netDial and netDialer are tiny shims so the ssl package doesn't
// import "net" at the top of ssl.go (which keeps the parser-only
// test cases from paying the import cost). They are referenced by
// the dial logic in ssl.go.

// netDial dials network/addr and returns the connection.
func netDial(network, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 200 * time.Millisecond}
	return d.Dial(network, addr)
}
