package systemd

import (
	"context"
	"syscall"

	"github.com/pkg/errors"

	"github.com/outofforest/cloudless/pkg/host"
	"github.com/outofforest/parallel"
)

// NewService returns systemd service.
func NewService() host.Service {
	return host.Service{
		Name:   "systemd",
		OnExit: parallel.Fail,
		TaskFn: func(ctx context.Context) error {
			return errors.WithStack(syscall.Exec("/usr/lib/systemd/systemd", []string{"--system"}, []string{}))
		},
	}
}
