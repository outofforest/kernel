package systemd

import (
	"syscall"

	"github.com/pkg/errors"
)

// Start starts systemd.
func Start() error {
	return errors.WithStack(syscall.Exec("/usr/lib/systemd/systemd", []string{"--system"}, []string{}))
}
