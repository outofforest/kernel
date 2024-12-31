package system

import (
	"syscall"

	"github.com/pkg/errors"
)

// StartSystemD starts systemd.
func StartSystemD() error {
	return errors.WithStack(syscall.Exec("/usr/lib/systemd/systemd", []string{"--system"}, []string{}))
}
