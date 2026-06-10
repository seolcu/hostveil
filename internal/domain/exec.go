package domain

import "os/exec"

// CommandRunner abstracts command execution for testability.
type CommandRunner interface {
	Output(cmd *exec.Cmd) ([]byte, error)
	Run(cmd *exec.Cmd) error
}

// DefaultRunner executes commands via os/exec.
type DefaultRunner struct{}

func (d DefaultRunner) Output(cmd *exec.Cmd) ([]byte, error) {
	return cmd.Output()
}

func (d DefaultRunner) Run(cmd *exec.Cmd) error {
	return cmd.Run()
}
