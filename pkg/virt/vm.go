package virt

import (
	"context"
	_ "embed"
	"os"

	"github.com/pkg/errors"

	"github.com/outofforest/cloudless/pkg/host"
	"github.com/outofforest/cloudless/pkg/kernel"
)

//go:embed vm.xml
var vmDef []byte

// VM creates VM.
func VM() host.Configurator {
	return func(c *host.Configuration) error {
		c.RequireInitramfs()
		c.RequireVirt()
		c.RequireKernelModules(kernel.Module{
			Name:   "kvm-intel",
			Params: "nested=Y",
		})
		c.Prepare(func(_ context.Context) error {
			if err := os.WriteFile("/etc/libvirt/qemu/test.xml", vmDef, 0o600); err != nil {
				return errors.WithStack(err)
			}
			return errors.WithStack(os.Link("/etc/libvirt/qemu/test.xml",
				"/etc/libvirt/qemu/autostart/test.xml"))
		})
		return nil
	}
}
