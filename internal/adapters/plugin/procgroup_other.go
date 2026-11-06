//go:build !unix

package plugin

import "os/exec"

// On platforms without process groups only the child itself is killed; a plugin that
// forks can outlive the deadline there. docs/PLUGINS.md says so.
func ownGroup(*exec.Cmd) {}

func killGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
