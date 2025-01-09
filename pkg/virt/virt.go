package virt

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/outofforest/cloudless/pkg/host"
	"github.com/outofforest/libexec"
	"github.com/outofforest/parallel"
)

// NewService creates new virtualization service.
func NewService() host.Service {
	return host.Service{
		Name:   "virt",
		OnExit: parallel.Fail,
		TaskFn: func(ctx context.Context) error {
			return parallel.Run(ctx, func(ctx context.Context, spawn parallel.SpawnFn) error {
				if err := setConfig(); err != nil {
					return err
				}

				for _, c := range []string{"virtqemud", "virtlogd", "virtstoraged", "virtnetworkd", "virtnodedevd"} {
					spawn(c, parallel.Fail, func(ctx context.Context) error {
						return libexec.Exec(ctx, exec.Command(filepath.Join("/usr/sbin", c)))
					})
				}

				return nil
			})
		},
	}
}

func setConfig() error {
	configF, err := os.OpenFile("/etc/libvirt/qemu.conf", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return errors.WithStack(err)
	}
	defer configF.Close()

	if _, err := configF.WriteString("\nuser = \"root\"\ngroup = \"root\"\n"); err != nil {
		return errors.WithStack(err)
	}

	return errors.WithStack(filepath.WalkDir("/etc/libvirt/qemu", func(path string, d os.DirEntry, err error) error {
		if !d.IsDir() {
			return os.Remove(path)
		}
		return nil
	}))
}
