package virt

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/outofforest/cloudless/pkg/host"
	"github.com/outofforest/cloudless/pkg/kernel"
	"github.com/outofforest/libexec"
	"github.com/outofforest/parallel"
)

var kernelModules = []kernel.Module{
	{
		Name: "tun",
	},
	{
		Name:   "kvm-intel",
		Params: "nested=Y",
	},
}

var packages = []string{
	"libvirt-daemon-config-network",
	"libvirt-daemon-kvm",
	"qemu-kvm",
	"qemu-virtiofsd",
	"libvirt-nss",
}

// NewService creates new virtualization service.
func NewService(objects ...ObjectSource) host.Service {
	return host.Service{
		Name:                 "virt",
		OnExit:               parallel.Fail,
		RequiresIPForwarding: true,
		RequiresInitramfs:    true,
		KernelModules:        kernelModules,
		Packages:             packages,
		ServiceFn: func(ctx context.Context, configurator *host.Configurator) error {
			return parallel.Run(ctx, func(ctx context.Context, spawn parallel.SpawnFn) error {
				if err := setConfig(); err != nil {
					return err
				}

				for _, o := range objects {
					if err := o(configurator); err != nil {
						return err
					}
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

// ObjectSource creates virtualized objects.
type ObjectSource func(configurator *host.Configurator) error

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
