package pxe

import (
	"context"

	"github.com/outofforest/cloudless/pkg/host"
	"github.com/outofforest/cloudless/pkg/host/firewall"
	"github.com/outofforest/cloudless/pkg/pxe/dhcp6"
	"github.com/outofforest/cloudless/pkg/pxe/tftp"
	"github.com/outofforest/parallel"
)

// Service returns PXE service.
func Service(efiDevPath string) host.Configurator {
	return func(c *host.Configuration) error {
		c.AddFirewallRules(
			firewall.OpenV6UDPPort(dhcp6.Port),
			firewall.OpenV6UDPPort(tftp.Port),
		)
		c.StartServices(host.ServiceConfig{
			Name:   "pxe",
			OnExit: parallel.Fail,
			TaskFn: func(ctx context.Context) error {
				return parallel.Run(ctx, func(ctx context.Context, spawn parallel.SpawnFn) error {
					spawn("dhcp6", parallel.Fail, dhcp6.Run)
					spawn("tftp", parallel.Fail, tftp.NewRun(efiDevPath))
					return nil
				})
			},
		})
		return nil
	}
}
