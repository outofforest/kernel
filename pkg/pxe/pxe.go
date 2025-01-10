package pxe

import (
	"context"

	"github.com/outofforest/cloudless/pkg/host"
	"github.com/outofforest/cloudless/pkg/host/firewall"
	"github.com/outofforest/cloudless/pkg/pxe/dhcp6"
	"github.com/outofforest/cloudless/pkg/pxe/tftp"
	"github.com/outofforest/parallel"
)

// NewService returns PXE service.
func NewService(efiDevPath string) host.Service {
	return host.Service{
		Name:   "pxe",
		OnExit: parallel.Fail,
		Firewall: []firewall.RuleSource{
			firewall.OpenV6UDPPort(dhcp6.Port),
			firewall.OpenV6UDPPort(tftp.Port),
		},
		ServiceFn: func(ctx context.Context, _ *host.Configurator) error {
			return parallel.Run(ctx, func(ctx context.Context, spawn parallel.SpawnFn) error {
				spawn("dhcp6", parallel.Fail, dhcp6.Run)
				spawn("tftp", parallel.Fail, tftp.NewRun(efiDevPath))
				return nil
			})
		},
	}
}
