package pxe

import (
	"context"

	"github.com/outofforest/cloudless/pkg/pxe/dhcp6"
	"github.com/outofforest/cloudless/pkg/pxe/tftp"
	"github.com/outofforest/parallel"
)

// NewRun returns Run function for PXE server.
func NewRun(efiDevPath string) parallel.Task {
	return func(ctx context.Context) error {
		return parallel.Run(ctx, func(ctx context.Context, spawn parallel.SpawnFn) error {
			spawn("dhcp6", parallel.Fail, dhcp6.Run)
			spawn("tftp", parallel.Fail, tftp.NewRun(efiDevPath))
			return nil
		})
	}
}
