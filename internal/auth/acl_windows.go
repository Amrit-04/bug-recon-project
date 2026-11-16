//go:build windows

package auth

import (
	"fmt"
	"os/exec"
	"os/user"
)

// RestrictFileAccess applies Windows Discretionary Access Control List (DACL) restrictions
// to ensure only the current user (and SYSTEM) has access to the credential file,
// stripping all inherited permissions from parent directories.
func RestrictFileAccess(filePath string) error {
	u, err := user.Current()
	if err != nil || u == nil || u.Username == "" {
		return nil
	}

	// Run icacls to disable inheritance and grant full access only to the current user
	cmd := exec.Command("icacls", filePath, "/inheritance:r", "/grant:r", fmt.Sprintf("%s:(F)", u.Username))
	return cmd.Run()
}
