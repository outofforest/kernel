package virt

import (
	"context"
	_ "embed"
	"os"

	"github.com/pkg/errors"

	"github.com/outofforest/cloudless/pkg/host"
	"github.com/outofforest/cloudless/pkg/host/firewall"
	"github.com/outofforest/cloudless/pkg/kernel"
)

//go:embed network.xml
var internalNetworkDef []byte

// NATedNetwork creates NATed network.
func NATedNetwork() host.Configurator {
	return func(c *host.Configuration) error {
		c.AddFirewallRules(
			firewall.ForwardTo("virint"),
			firewall.ForwardFrom("virint"),
			firewall.Masquerade("virint"),
		)
		c.RequireIPForwarding()
		c.RequireVirt()
		c.RequireKernelModules(kernel.Module{
			Name: "tun",
		})
		c.Prepare(func(_ context.Context) error {
			if err := os.WriteFile("/etc/libvirt/qemu/networks/internal.xml", internalNetworkDef,
				0o600); err != nil {
				return errors.WithStack(err)
			}
			return errors.WithStack(os.Link("/etc/libvirt/qemu/networks/internal.xml",
				"/etc/libvirt/qemu/networks/autostart/internal.xml"))
		})

		return nil
	}
}
