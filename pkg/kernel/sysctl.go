package kernel

import (
	"os"
	"path/filepath"

	"github.com/pkg/errors"
)

// SetSysctl sets sysctl value.
func SetSysctl(path string, value string) error {
	return errors.WithStack(os.WriteFile(filepath.Join("/proc/sys", path), []byte(value), 0o644))
}
