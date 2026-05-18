package adapter

import (
	"bytes"
	"context"
	"os/exec"
	"time"
)

type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Err      error
}

const DefaultTimeout = 5 * time.Minute

func RunCommand(name string, args ...string) Result {
	return RunCommandWithTimeout(DefaultTimeout, name, args...)
}

func RunCommandWithTimeout(timeout time.Duration, name string, args ...string) Result {
	var stdout, stderr bytes.Buffer

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		}
		if ctx.Err() == context.DeadlineExceeded {
			err = CommandTimeoutError{Name: name, Timeout: timeout}
		}
	}

	return Result{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: exitCode,
		Err:      err,
	}
}

type CommandTimeoutError struct {
	Name    string
	Timeout time.Duration
}

func (e CommandTimeoutError) Error() string {
	return e.Name + " timed out after " + e.Timeout.String()
}

func IsAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
