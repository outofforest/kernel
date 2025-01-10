package virt

import (
	_ "embed"
	"os"

	"github.com/pkg/errors"

	"github.com/outofforest/cloudless/pkg/host"
	"github.com/outofforest/cloudless/pkg/host/firewall"
)

//go:embed network.xml
var internalNetworkDef []byte

// NATedNetwork creates NATed network.
func NATedNetwork() ObjectSource {
	return func(configurator *host.Configurator) error {
		defaultIface, err := host.DefaultIface()
		if err != nil {
			return err
		}
		if err := configurator.AddFirewallRules(
			firewall.ForwardTo("virint"),
			firewall.ForwardFrom("virint"),
			firewall.Masquerade("virint", defaultIface),
		); err != nil {
			return err
		}

		if err := os.WriteFile("/etc/libvirt/qemu/networks/internal.xml", internalNetworkDef, 0o600); err != nil {
			return errors.WithStack(err)
		}
		return errors.WithStack(os.Link("/etc/libvirt/qemu/networks/internal.xml",
			"/etc/libvirt/qemu/networks/autostart/internal.xml"))
	}
}
