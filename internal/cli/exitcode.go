package cli

// Exit codes for the hostveil process.
//
// 0  no high-severity or critical finding
// 1  at least one high-severity or critical finding was detected
// 2  scan errored
const (
	ExitOK   = 0
	ExitHit  = 1
	ExitError = 2
)
