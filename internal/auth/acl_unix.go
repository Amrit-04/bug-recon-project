//go:build !windows

package auth

import (
	"os"
)

// RestrictFileAccess sets strict POSIX permissions (0600) on the credential file.
func RestrictFileAccess(filePath string) error {
	return os.Chmod(filePath, 0600)
}
