//go:build windows

package tools

import (
	"os/exec"
	"strconv"
)

func configureCommandCancellation(cmd *exec.Cmd) {
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// Terminate the entire process tree on Windows to ensure no child processes are orphaned
		killCmd := exec.Command("taskkill", "/F", "/T", "/PID", strconv.Itoa(cmd.Process.Pid))
		_ = killCmd.Run()
		return cmd.Process.Kill()
	}
}
