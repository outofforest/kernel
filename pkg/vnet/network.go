package vnet

import (
	"context"
	_ "embed"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/samber/lo"

	"github.com/outofforest/cloudless/pkg/host"
	"github.com/outofforest/cloudless/pkg/host/firewall"
	"github.com/outofforest/cloudless/pkg/kernel"
	"github.com/outofforest/cloudless/pkg/parse"
)

var (
	//go:embed nat.tmpl.xml
	natDef string

	natDefTmpl = lo.Must(template.New("nat").Parse(natDef))
)

// Network represents network configuration.
type Network struct {
	UUID      uuid.UUID
	Name      string
	IfaceName string
	MAC       net.HardwareAddr
	IP4       net.IPNet
	IP6       net.IPNet
}

// Configurator defines function setting the network configuration.
type Configurator func(m *Network)

// NAT creates NATed network.
func NAT(name, mac string, configurators ...Configurator) host.Configurator {
	return func(c *host.Configuration) error {
		netUUID, err := uuid.NewUUID()
		if err != nil {
			return errors.WithStack(err)
		}
		n := Network{
			UUID:      netUUID,
			Name:      name,
			IfaceName: "v" + strings.ToLower(name),
			MAC:       parse.MAC(mac),
		}
		if len(n.IfaceName) > 15 {
			n.IfaceName = n.IfaceName[:15]
		}

		for _, configurator := range configurators {
			configurator(&n)
		}

		c.AddFirewallRules(
			firewall.ForwardTo(n.IfaceName),
			firewall.ForwardFrom(n.IfaceName),
			firewall.Masquerade(n.IfaceName),
		)
		c.RequireIPForwarding()
		c.RequireVirt()
		c.RequireKernelModules(kernel.Module{
			Name: "tun",
		})
		c.Prepare(func(_ context.Context) error {
			filePath := fmt.Sprintf("/etc/libvirt/qemu/networks/%s.xml", n.Name)
			f, err := os.OpenFile(filePath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
			if err != nil {
				return errors.WithStack(err)
			}
			defer f.Close()

			data := struct {
				UUID      uuid.UUID
				Name      string
				IfaceName string
				MAC       net.HardwareAddr
				IP4       net.IP
				IP4Mask   string
				IP6       net.IP
				IP6Prefix int
			}{
				UUID:      n.UUID,
				Name:      n.Name,
				IfaceName: n.IfaceName,
				MAC:       n.MAC,
				IP4:       n.IP4.IP,
				IP6:       n.IP6.IP,
			}

			if n.IP4.Mask != nil {
				data.IP4Mask = fmt.Sprintf("%d.%d.%d.%d", n.IP4.Mask[0], n.IP4.Mask[1], n.IP4.Mask[2],
					n.IP4.Mask[3])
			}
			if n.IP6.Mask != nil {
				data.IP6Prefix, _ = n.IP6.Mask.Size()
			}

			if err := natDefTmpl.Execute(f, data); err != nil {
				return errors.WithStack(err)
			}

			return errors.WithStack(os.Link(filePath,
				filepath.Join(filepath.Dir(filePath), "autostart", filepath.Base(filePath))))
		})

		return nil
	}
}

// IP4 configures network's IPv4 address on the host.
func IP4(ip string) Configurator {
	return func(n *Network) {
		n.IP4 = parse.IPNet4(ip)
	}
}

// IP6 configures network's IPv6 address on the host.
func IP6(ip string) Configurator {
	return func(n *Network) {
		n.IP6 = parse.IPNet6(ip)
	}
}
